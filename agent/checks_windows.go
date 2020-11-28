package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	ps "github.com/elastic/go-sysinfo"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
)

type AssignedTask struct {
	TaskPK  int  `json:"id"`
	Enabled bool `json:"enabled"`
}

type Script struct {
	Shell string `json:"shell"`
	Code  string `json:"code"`
}

type CheckInfo struct {
	AgentPK  int `json:"agent"`
	Interval int `json:"check_interval"`
}

type Check struct {
	Script           Script         `json:"script"`
	AssignedTasks    []AssignedTask `json:"assigned_tasks"`
	CheckPK          int            `json:"id"`
	CheckType        string         `json:"check_type"`
	Status           string         `json:"status"`
	Threshold        int            `json:"threshold"`
	Disk             string         `json:"disk"`
	IP               string         `json:"ip"`
	ScriptArgs       []string       `json:"script_args"`
	Timeout          int            `json:"timeout"`
	ServiceName      string         `json:"svc_name"`
	PassStartPending bool           `json:"pass_if_start_pending"`
	PassNotExist     bool           `json:"pass_if_svc_not_exist"`
	RestartIfStopped bool           `json:"restart_if_stopped"`
	LogName          string         `json:"log_name"`
	EventID          int            `json:"event_id"`
	EventIDWildcard  bool           `json:"event_id_is_wildcard"`
	EventType        string         `json:"event_type"`
	EventSource      string         `json:"event_source"`
	EventMessage     string         `json:"event_message"`
	FailWhen         string         `json:"fail_when"`
	SearchLastDays   int            `json:"search_last_days"`
}

type AllChecks struct {
	CheckInfo
	Checks []Check
}

func (a *WindowsAgent) CheckRunner() {
	a.Logger.Infoln("Checkrunner service started.")
	a.Logger.Debugln("Sleeping for 15 seconds")
	time.Sleep(15 * time.Second)
	for {
		interval, _ := a.RunChecks()
		a.Logger.Debugln("Sleeping for", interval)
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func (a *WindowsAgent) RunChecks() (int, error) {
	data := AllChecks{}
	url := fmt.Sprintf("%s/api/v3/%s/checkrunner/", a.Server, a.AgentID)
	req := APIRequest{
		URL:       url,
		Method:    "GET",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return 120, err
	}

	if err := json.Unmarshal(r.Body(), &data); err != nil {
		a.Logger.Debugln(err)
		return 120, err
	}

	var wg sync.WaitGroup
	for _, check := range data.Checks {
		switch check.CheckType {
		case "diskspace":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.DiskCheck(c)
			}(check, &wg)
		case "cpuload":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.CPULoadCheck(c)
			}(check, &wg)
		case "memory":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.MemCheck(c)
			}(check, &wg)
		case "ping":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.PingCheck(c)
			}(check, &wg)
		case "script":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.ScriptCheck(c)
			}(check, &wg)
		case "winsvc":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.WinSvcCheck(c)
			}(check, &wg)
		case "eventlog":
			wg.Add(1)
			go func(c Check, wg *sync.WaitGroup) {
				defer wg.Done()
				a.EventLogCheck(c)
			}(check, &wg)
		default:
			continue
		}
	}
	wg.Wait()
	return data.CheckInfo.Interval, nil
}

func (a *WindowsAgent) RunScript(code string, shell string, args []string, timeout int) (stdout, stderr string, exitcode int, e error) {

	content := []byte(code)

	dir, err := ioutil.TempDir("", "trmm")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}
	defer os.RemoveAll(dir)

	const defaultExitCode = 1

	var (
		outb    bytes.Buffer
		errb    bytes.Buffer
		exe     string
		ext     string
		cmdArgs []string
	)

	switch shell {
	case "powershell":
		ext = "*.ps1"
	case "python":
		ext = "*.py"
	case "cmd":
		ext = "*.bat"
	}

	tmpfn, _ := ioutil.TempFile(dir, ext)
	if _, err := tmpfn.Write(content); err != nil {
		a.Logger.Debugln(err)
		return "", err.Error(), 85, err
	}
	if err := tmpfn.Close(); err != nil {
		a.Logger.Debugln(err)
		return "", err.Error(), 85, err
	}

	switch shell {
	case "powershell":
		exe = "Powershell"
		cmdArgs = []string{"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", tmpfn.Name()}
	case "python":
		exe = a.PyBin
		cmdArgs = []string{tmpfn.Name()}
	case "cmd":
		exe = tmpfn.Name()
	}

	if len(args) > 0 {
		cmdArgs = append(cmdArgs, args...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var timedOut bool = false
	cmd := exec.Command(exe, cmdArgs...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	if cmdErr := cmd.Start(); cmdErr != nil {
		a.Logger.Debugln(cmdErr)
		return "", cmdErr.Error(), 65, cmdErr
	}
	pid := int32(cmd.Process.Pid)

	// custom context handling, we need to kill child procs if this is a batch script,
	// otherwise it will hang forever
	// the normal exec.CommandContext() doesn't work since it only kills the parent process
	go func(p int32) {

		<-ctx.Done()

		_ = KillProc(p)
		timedOut = true
	}(pid)

	cmdErr := cmd.Wait()

	if timedOut {
		stdout = outb.String()
		stderr = fmt.Sprintf("%s\nScript timed out after %d seconds", errb.String(), timeout)
		exitcode = 98
		a.Logger.Debugln("Script check timeout:", ctx.Err())
	} else {
		stdout = outb.String()
		stderr = errb.String()

		// get the exit code
		if cmdErr != nil {
			if exitError, ok := cmdErr.(*exec.ExitError); ok {
				if ws, ok := exitError.Sys().(syscall.WaitStatus); ok {
					exitcode = ws.ExitStatus()
				} else {
					exitcode = defaultExitCode
				}
			} else {
				exitcode = defaultExitCode
			}

		} else {
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
				exitcode = ws.ExitStatus()
			} else {
				exitcode = 0
			}
		}
	}
	return stdout, stderr, exitcode, nil
}

// ScriptCheck runs either bat, powershell or python script
func (a *WindowsAgent) ScriptCheck(data Check) {
	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   30,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	start := time.Now()
	stdout, stderr, retcode, _ := a.RunScript(data.Script.Code, data.Script.Shell, data.ScriptArgs, data.Timeout)

	r.Payload = map[string]interface{}{
		"id":      data.CheckPK,
		"stdout":  stdout,
		"stderr":  stderr,
		"retcode": retcode,
		"runtime": time.Since(start).Seconds(),
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// DiskCheck checks disk usage
func (a *WindowsAgent) DiskCheck(data Check) {
	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	usage, err := disk.Usage(data.Disk)
	if err != nil {
		a.Logger.Debugln("Disk", data.Disk, err)
		r.Payload = map[string]interface{}{"id": data.CheckPK, "exists": false}
		if _, err := r.MakeRequest(); err != nil {
			a.Logger.Debugln(err)
		}
		return
	}

	r.Payload = map[string]interface{}{
		"id":           data.CheckPK,
		"exists":       true,
		"percent_used": usage.UsedPercent,
		"total":        usage.Total,
		"free":         usage.Free,
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// CPULoadCheck checks avg cpu load
func (a *WindowsAgent) CPULoadCheck(data Check) {
	percent, err := cpu.Percent(10*time.Second, false)
	if err != nil {
		a.Logger.Debugln("CPU Check:", err)
		return
	}

	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r.Payload = map[string]interface{}{
		"id":      data.CheckPK,
		"percent": int(math.Round(percent[0])),
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// MemCheck checks mem percentage
func (a *WindowsAgent) MemCheck(data Check) {
	host, _ := ps.Host()
	mem, _ := host.Memory()
	percent := (float64(mem.Used) / float64(mem.Total)) * 100

	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r.Payload = map[string]interface{}{
		"id":      data.CheckPK,
		"percent": int(math.Round(percent)),
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) EventLogCheck(data Check) {
	evtLog := a.GetEventLog(data.LogName, data.SearchLastDays)

	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   30,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r.Payload = map[string]interface{}{
		"id":  data.CheckPK,
		"log": evtLog,
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) PingCheck(data Check) {
	cmdArgs := []string{data.IP}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(90)*time.Second)
	defer cancel()

	var (
		outb   bytes.Buffer
		errb   bytes.Buffer
		hasOut bool
		hasErr bool
		output string
	)
	cmd := exec.CommandContext(ctx, "ping", cmdArgs...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	cmdErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		a.Logger.Debugln("Ping check:", ctx.Err())
		hasErr = true
		output = fmt.Sprintf("Ping check %s timed out", data.IP)
	} else if cmdErr != nil || errb.String() != "" {
		hasErr = true
		output = fmt.Sprintf("%s\n%s", outb.String(), errb.String())
	} else {
		hasOut = true
		output = outb.String()
	}

	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r.Payload = map[string]interface{}{
		"id":         data.CheckPK,
		"has_stdout": hasOut,
		"has_stderr": hasErr,
		"output":     output,
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)

}

func (a *WindowsAgent) WinSvcCheck(data Check) {
	var status string
	exists := true
	url := a.Server + "/api/v3/checkrunner/"
	r := APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	status, err := GetServiceStatus(data.ServiceName)
	if err != nil {
		exists = false
		status = "n/a"
		a.Logger.Debugln("Service", data.ServiceName, err)
	}

	r.Payload = map[string]interface{}{
		"id":     data.CheckPK,
		"exists": exists,
		"status": status,
	}

	resp, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) handleAssignedTasks(status string, tasks []AssignedTask) {
	if len(tasks) > 0 && DjangoStringResp(status) == "failing" {
		var wg sync.WaitGroup
		for _, t := range tasks {
			if t.Enabled {
				wg.Add(1)
				go func(pk int, wg *sync.WaitGroup) {
					defer wg.Done()
					a.RunTask(pk)
				}(t.TaskPK, &wg)
			}
		}
		wg.Wait()
	}
}
