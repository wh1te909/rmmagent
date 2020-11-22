package agent

import (
	"encoding/json"
	"fmt"
	"time"
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
