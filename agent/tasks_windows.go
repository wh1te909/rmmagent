package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/capnspacehook/taskmaster"
)

type AutomatedTask struct {
	ID         int      `json:"id"`
	TaskScript Script   `json:"script"`
	Timeout    int      `json:"timeout"`
	Enabled    bool     `json:"enabled"`
	Args       []string `json:"script_args"`
}

func (a *WindowsAgent) RunTask(id int) error {
	data := AutomatedTask{}
	url := fmt.Sprintf("%s/api/v3/%d/%s/taskrunner/", a.Server, id, a.AgentID)
	r := APIRequest{
		URL:       url,
		Method:    "GET",
		Headers:   a.Headers,
		Timeout:   30,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r1, gerr := r.MakeRequest()
	if gerr != nil {
		a.Logger.Debugln(gerr)
		return gerr
	}

	if r1.IsError() {
		a.Logger.Debugln("Run Task:", r1.String())
		return nil
	}

	if err := json.Unmarshal(r1.Body(), &data); err != nil {
		a.Logger.Debugln(err)
		return err
	}

	start := time.Now()
	stdout, stderr, retcode, _ := a.RunScript(data.TaskScript.Code, data.TaskScript.Shell, data.Args, data.Timeout)

	type TaskResult struct {
		Stdout   string  `json:"stdout"`
		Stderr   string  `json:"stderr"`
		RetCode  int     `json:"retcode"`
		ExecTime float64 `json:"execution_time"`
	}

	r.Method = "PATCH"
	r.Payload = TaskResult{Stdout: stdout, Stderr: stderr, RetCode: retcode, ExecTime: time.Since(start).Seconds()}

	_, perr := r.MakeRequest()
	if perr != nil {
		a.Logger.Debugln(perr)
		return perr
	}
	return nil
}

// CreateInternalTask creates predefined tacticalrmm internal tasks
func (a *WindowsAgent) CreateInternalTask(name, args, repeat string, start int) (bool, error) {
	conn, err := taskmaster.Connect()
	if err != nil {
		return false, err
	}
	defer conn.Disconnect()

	def := conn.NewTaskDefinition()

	dailyTrigger := taskmaster.DailyTrigger{
		TaskTrigger: taskmaster.TaskTrigger{
			Enabled:       true,
			StartBoundary: time.Now().Add(time.Duration(start) * time.Minute),
		},
		DayInterval: taskmaster.EveryDay,
	}

	def.AddTrigger(dailyTrigger)

	action := taskmaster.ExecAction{
		Path:       a.EXE,
		WorkingDir: a.ProgramDir,
		Args:       args,
	}
	def.AddAction(action)

	def.Principal.RunLevel = taskmaster.TASK_RUNLEVEL_HIGHEST
	def.Principal.LogonType = taskmaster.TASK_LOGON_SERVICE_ACCOUNT
	def.Principal.UserID = "SYSTEM"
	def.Settings.AllowDemandStart = true
	def.Settings.AllowHardTerminate = true
	def.Settings.DontStartOnBatteries = false
	def.Settings.Enabled = true
	def.Settings.MultipleInstances = taskmaster.TASK_INSTANCES_PARALLEL
	def.Settings.StopIfGoingOnBatteries = false
	def.Settings.WakeToRun = true

	_, success, err := conn.CreateTask(fmt.Sprintf("\\%s", name), def, true)
	if err != nil {
		return false, err
	}

	if success {
		// https://github.com/capnspacehook/taskmaster/issues/15
		out, err := CMD("schtasks", []string{"/Change", "/TN", name, "/RI", repeat}, 10, false)
		if err != nil {
			return false, err
		}
		if out[1] != "" {
			a.Logger.Errorln(out[1])
			return false, nil
		}
		return success, nil
	}
	return false, nil
}

// CleanupSchedTasks removes all tacticalrmm sched tasks during uninstall
func CleanupSchedTasks() {
	conn, err := taskmaster.Connect()
	if err != nil {
		return
	}
	defer conn.Disconnect()

	tasks, err := conn.GetRegisteredTasks()
	if err != nil {
		return
	}

	for _, task := range tasks {
		if strings.HasPrefix(task.Name, "TacticalRMM_") {
			defer task.Release()
			conn.DeleteTask(fmt.Sprintf("\\%s", task.Name))
		}
	}
}
