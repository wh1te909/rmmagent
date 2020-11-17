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
	"strconv"
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
	req := &APIRequest{
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
			go func(c Check) {
				defer wg.Done()
				a.DiskCheck(c)
			}(check)
		case "cpuload":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.CPULoadCheck(c)
			}(check)
		case "memory":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.MemCheck(c)
			}(check)
		case "ping":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.PingCheck(c)
			}(check)
		case "script":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.ScriptCheck(c)
			}(check)
		case "winsvc":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.WinSvcCheck(c)
			}(check)
		case "eventlog":
			wg.Add(1)
			go func(c Check) {
				defer wg.Done()
				a.EventLogCheck(c)
			}(check)
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
		stderr = fmt.Sprintf("%s\nScript check timed out after %d seconds", errb.String(), timeout)
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
	r := &APIRequest{
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
	r := &APIRequest{
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
	r := &APIRequest{
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
	r := &APIRequest{
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
	content := []byte(eventLogPyScript)
	dir, err := ioutil.TempDir("", "pyevtlog")
	if err != nil {
		a.Logger.Debugln(err)
		return
	}
	defer os.RemoveAll(dir)

	tmpfn, _ := ioutil.TempFile(dir, "*.py")
	if _, err := tmpfn.Write(content); err != nil {
		a.Logger.Debugln(err)
		return
	}
	if err := tmpfn.Close(); err != nil {
		a.Logger.Debugln(err)
		return
	}

	cmdArgs := []string{tmpfn.Name(), data.LogName, strconv.Itoa(data.SearchLastDays)}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(180)*time.Second)
	defer cancel()

	var outb, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, a.PyBin, cmdArgs...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	cmdErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		a.Logger.Debugln("Event log check:", ctx.Err())
		return
	}

	if cmdErr != nil {
		a.Logger.Debugln("Event log check:", cmdErr)
		return
	}

	if errb.String() != "" {
		a.Logger.Debugln("Event log check:", errb.String())
		return
	}

	url := a.Server + "/api/v3/checkrunner/"
	r := &APIRequest{
		URL:       url,
		Method:    "PATCH",
		Headers:   a.Headers,
		Timeout:   30,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r.Payload = map[string]interface{}{
		"id":  data.CheckPK,
		"log": outb.String(),
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
	r := &APIRequest{
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
	r := &APIRequest{
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
				go func(pk int) {
					defer wg.Done()
					a.RunTask(pk)
				}(t.TaskPK)
			}
		}
		wg.Wait()
	}
}

// temp until rewrite this in go
var eventLogPyScript = `
import base64
import json
import sys
import zlib
import datetime as dt

import win32con
import win32evtlog
import win32evtlogutil
import winerror

try:
	log = []
	api_log_name = str(sys.argv[1])
	api_search_last_days = int(sys.argv[2])

	if api_search_last_days != 0:
		start_time = dt.datetime.now() - dt.timedelta(days=api_search_last_days)

	flags = (win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ)

	status_dict = {
		win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
		win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
		win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
		win32con.EVENTLOG_WARNING_TYPE: "WARNING",
		win32con.EVENTLOG_ERROR_TYPE: "ERROR",
		0: "INFO",
	}

	hand = win32evtlog.OpenEventLog("localhost", api_log_name)
	total = win32evtlog.GetNumberOfEventLogRecords(hand)
	uid = 0
	done = False

	while 1:
		events = win32evtlog.ReadEventLog(hand, flags, 0)
		for ev_obj in events:

			uid += 1
			# return once total number of events reach or we'll be stuck in an infinite loop
			if uid >= total:
				done = True
				break

			the_time = ev_obj.TimeGenerated.Format()
			time_obj = dt.datetime.strptime(the_time, "%c")

			if api_search_last_days != 0:
				if time_obj < start_time:
					done = True
					break

			computer = str(ev_obj.ComputerName)
			src = str(ev_obj.SourceName)
			evt_type = str(status_dict[ev_obj.EventType])
			evt_id = str(winerror.HRESULT_CODE(ev_obj.EventID))
			evt_category = str(ev_obj.EventCategory)
			record = str(ev_obj.RecordNumber)
			msg = (
				str(win32evtlogutil.SafeFormatMessage(ev_obj, api_log_name))
				.replace("<", "")
				.replace(">", "")
			)

			event_dict = {
				"computer": computer,
				"source": src,
				"eventType": evt_type,
				"eventID": evt_id,
				"eventCategory": evt_category,
				"message": msg,
				"time": the_time,
				"record": record,
				"uid": uid,
			}
			log.append(event_dict)

		if done:
			break

	win32evtlog.CloseEventLog(hand)

	encoded = base64.b64encode(zlib.compress(json.dumps(log).encode("utf-8", errors="ignore"))).decode("ascii", errors="ignore")
	print(encoded, end='')
except:
	print("", end='')
`
