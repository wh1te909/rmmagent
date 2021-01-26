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
	"github.com/go-resty/resty/v2"
	"github.com/shirou/gopsutil/v3/disk"
	rmm "github.com/wh1te909/rmmagent/shared"
)

func (a *WindowsAgent) CheckRunner() {
	a.Logger.Infoln("Checkrunner service started.")
	sleepDelay := randRange(14, 22)
	a.Logger.Debugf("Sleeping for %v seconds", sleepDelay)
	time.Sleep(time.Duration(sleepDelay) * time.Second)
	for {
		interval, err := a.GetCheckInterval()
		if err == nil {
			_, err = CMD(a.EXE, []string{"-m", "runchecks"}, 600, false)
			if err != nil {
				a.Logger.Errorln("Checkrunner RunChecks", err)
			}
		}
		a.Logger.Debugln("Checkrunner sleeping for", interval)
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func (a *WindowsAgent) GetCheckInterval() (int, error) {
	r, err := a.rClient.R().SetResult(&rmm.CheckInfo{}).Get(fmt.Sprintf("/api/v3/%s/checkinterval/", a.AgentID))
	if err != nil {
		a.Logger.Debugln(err)
		return 120, err
	}
	if r.IsError() {
		a.Logger.Debugln("Checkinterval response code:", r.StatusCode())
		return 120, fmt.Errorf("checkinterval response code: %v", r.StatusCode())
	}
	interval := r.Result().(*rmm.CheckInfo).Interval
	return interval, nil
}

func (a *WindowsAgent) RunChecks() error {
	data := rmm.AllChecks{}
	r, err := a.rClient.R().Get(fmt.Sprintf("/api/v3/%s/checkrunner/", a.AgentID))
	if err != nil {
		a.Logger.Debugln(err)
		return err
	}

	if r.IsError() {
		a.Logger.Debugln("Checkrunner response code:", r.StatusCode())
		return nil
	}

	if err := json.Unmarshal(r.Body(), &data); err != nil {
		a.Logger.Debugln(err)
		return err
	}

	var wg sync.WaitGroup
	eventLogChecks := make([]rmm.Check, 0)
	winServiceChecks := make([]rmm.Check, 0)

	for _, check := range data.Checks {
		switch check.CheckType {
		case "diskspace":
			wg.Add(1)
			go func(c rmm.Check, wg *sync.WaitGroup, r *resty.Client) {
				defer wg.Done()
				time.Sleep(time.Duration(randRange(300, 950)) * time.Millisecond)
				a.DiskCheck(c, r)
			}(check, &wg, a.rClient)
		case "cpuload":
			wg.Add(1)
			go func(c rmm.Check, wg *sync.WaitGroup, r *resty.Client) {
				defer wg.Done()
				a.CPULoadCheck(c, r)
			}(check, &wg, a.rClient)
		case "memory":
			wg.Add(1)
			go func(c rmm.Check, wg *sync.WaitGroup, r *resty.Client) {
				defer wg.Done()
				time.Sleep(time.Duration(randRange(300, 950)) * time.Millisecond)
				a.MemCheck(c, r)
			}(check, &wg, a.rClient)
		case "ping":
			wg.Add(1)
			go func(c rmm.Check, wg *sync.WaitGroup, r *resty.Client) {
				defer wg.Done()
				time.Sleep(time.Duration(randRange(300, 950)) * time.Millisecond)
				a.PingCheck(c, r)
			}(check, &wg, a.rClient)
		case "script":
			wg.Add(1)
			go func(c rmm.Check, wg *sync.WaitGroup, r *resty.Client) {
				defer wg.Done()
				time.Sleep(time.Duration(randRange(300, 950)) * time.Millisecond)
				a.ScriptCheck(c, r)
			}(check, &wg, a.rClient)
		case "winsvc":
			winServiceChecks = append(winServiceChecks, check)
		case "eventlog":
			eventLogChecks = append(eventLogChecks, check)
		default:
			continue
		}
	}

	go func(wg *sync.WaitGroup, r *resty.Client) {
		for _, winSvcCheck := range winServiceChecks {
			time.Sleep(200 * time.Millisecond)
			wg.Add(1)
			a.WinSvcCheck(winSvcCheck, r)
			wg.Done()
		}
	}(&wg, a.rClient)

	go func(wg *sync.WaitGroup, r *resty.Client) {
		for _, evtCheck := range eventLogChecks {
			wg.Add(1)
			a.EventLogCheck(evtCheck, r)
			wg.Done()
		}
	}(&wg, a.rClient)

	wg.Wait()
	return nil
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
func (a *WindowsAgent) ScriptCheck(data rmm.Check, r *resty.Client) {
	start := time.Now()
	stdout, stderr, retcode, _ := a.RunScript(data.Script.Code, data.Script.Shell, data.ScriptArgs, data.Timeout)

	payload := map[string]interface{}{
		"id":      data.CheckPK,
		"stdout":  stdout,
		"stderr":  stderr,
		"retcode": retcode,
		"runtime": time.Since(start).Seconds(),
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// DiskCheck checks disk usage
func (a *WindowsAgent) DiskCheck(data rmm.Check, r *resty.Client) {
	var payload map[string]interface{}

	usage, err := disk.Usage(data.Disk)
	if err != nil {
		a.Logger.Debugln("Disk", data.Disk, err)
		payload = map[string]interface{}{"id": data.CheckPK, "exists": false}
		if _, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/"); err != nil {
			a.Logger.Debugln(err)
		}
		return
	}

	payload = map[string]interface{}{
		"id":           data.CheckPK,
		"exists":       true,
		"percent_used": usage.UsedPercent,
		"total":        usage.Total,
		"free":         usage.Free,
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// CPULoadCheck checks avg cpu load
func (a *WindowsAgent) CPULoadCheck(data rmm.Check, r *resty.Client) {
	payload := map[string]interface{}{
		"id":      data.CheckPK,
		"percent": a.GetCPULoadAvg(),
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

// MemCheck checks mem percentage
func (a *WindowsAgent) MemCheck(data rmm.Check, r *resty.Client) {
	host, _ := ps.Host()
	mem, _ := host.Memory()
	percent := (float64(mem.Used) / float64(mem.Total)) * 100

	payload := map[string]interface{}{
		"id":      data.CheckPK,
		"percent": int(math.Round(percent)),
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) EventLogCheck(data rmm.Check, r *resty.Client) {
	evtLog := a.GetEventLog(data.LogName, data.SearchLastDays)
	payload := map[string]interface{}{
		"id":  data.CheckPK,
		"log": evtLog,
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) PingCheck(data rmm.Check, r *resty.Client) {
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

	payload := map[string]interface{}{
		"id":         data.CheckPK,
		"has_stdout": hasOut,
		"has_stderr": hasErr,
		"output":     output,
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) WinSvcCheck(data rmm.Check, r *resty.Client) {
	var status string
	exists := true

	status, err := GetServiceStatus(data.ServiceName)
	if err != nil {
		exists = false
		status = "n/a"
		a.Logger.Debugln("Service", data.ServiceName, err)
	}

	payload := map[string]interface{}{
		"id":     data.CheckPK,
		"exists": exists,
		"status": status,
	}

	resp, err := r.R().SetBody(payload).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.handleAssignedTasks(resp.String(), data.AssignedTasks)
}

func (a *WindowsAgent) handleAssignedTasks(status string, tasks []rmm.AssignedTask) {
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
