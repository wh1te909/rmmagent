package agent

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

type NatsMsg struct {
	Func          string            `json:"func"`
	Timeout       int               `json:"timeout"`
	Data          map[string]string `json:"payload"`
	ScriptArgs    []string          `json:"script_args"`
	ProcPID       int32             `json:"procpid"`
	TaskPK        int               `json:"taskpk"`
	ScheduledTask SchedTask         `json:"schedtaskpayload"`
}

func (a *WindowsAgent) RunRPC() {
	a.Logger.Infoln("RPC service started")
	a.Logger.Debugln("Sleeping for 15 seconds")
	time.Sleep(15 * time.Second)

	opts := []nats.Option{nats.Name("TacticalRMM"), nats.UserInfo(a.AgentID, a.Token)}
	opts = setupConnOptions(opts)

	server := fmt.Sprintf("tls://%s:4222", a.SaltMaster)
	nc, err := nats.Connect(server, opts...)
	if err != nil {
		a.Logger.Errorln(err)
	}

	nc.Subscribe(a.AgentID, func(msg *nats.Msg) {
		a.Logger.SetOutput(os.Stdout)
		var payload *NatsMsg
		var mh codec.MsgpackHandle
		mh.RawToString = true

		dec := codec.NewDecoderBytes(msg.Data, &mh)
		if err := dec.Decode(&payload); err != nil {
			a.Logger.Errorln(err)
			return
		}

		switch payload.Func {
		case "ping":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				a.Logger.Debugln("pong")
				ret.Encode("pong")
				msg.Respond(resp)
			}()

		case "schedtask":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				success, err := a.CreateSchedTask(p.ScheduledTask)
				if err != nil {
					a.Logger.Errorln(err.Error())
					ret.Encode(err.Error())
				} else if !success {
					ret.Encode("Something went wrong")
				} else {
					ret.Encode("ok")
				}
				msg.Respond(resp)
			}(payload)

		case "delschedtask":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				err := DeleteSchedTask(p.ScheduledTask.Name)
				if err != nil {
					a.Logger.Errorln(err.Error())
					ret.Encode(err.Error())
				} else {
					ret.Encode("ok")
				}
				msg.Respond(resp)
			}(payload)

		case "enableschedtask":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				err := EnableSchedTask(p.ScheduledTask)
				if err != nil {
					a.Logger.Errorln(err.Error())
					ret.Encode(err.Error())
				} else {
					ret.Encode("ok")
				}
				msg.Respond(resp)
			}(payload)

		case "listschedtasks":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				tasks := ListSchedTasks()
				a.Logger.Debugln(tasks)
				ret.Encode(tasks)
				msg.Respond(resp)
			}()

		case "eventlog":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				days, _ := strconv.Atoi(p.Data["days"])
				evtLog := a.GetEventLog(p.Data["logname"], days)
				a.Logger.Debugln(evtLog)
				ret.Encode(evtLog)
				msg.Respond(resp)
			}(payload)

		case "procs":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				procs := a.GetProcsRPC()
				a.Logger.Debugln(procs)
				ret.Encode(procs)
				msg.Respond(resp)
			}()

		case "killproc":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				err := KillProc(p.ProcPID)
				if err != nil {
					ret.Encode(err.Error())
					a.Logger.Debugln(err.Error())
				} else {
					ret.Encode("ok")
				}
				msg.Respond(resp)
			}(payload)

		case "rawcmd":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				out, _ := CMDShell(p.Data["shell"], []string{}, p.Data["command"], p.Timeout, false)
				a.Logger.Debugln(out)
				if out[1] != "" {
					ret.Encode(out[1])
				} else {
					ret.Encode(out[0])
				}

				msg.Respond(resp)
			}(payload)

		case "winservices":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				svcs := a.GetServices()
				a.Logger.Debugln(svcs)
				ret.Encode(svcs)
				msg.Respond(resp)
			}()

		case "winsvcdetail":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				svc := a.GetServiceDetail(p.Data["name"])
				a.Logger.Debugln(svc)
				ret.Encode(svc)
				msg.Respond(resp)
			}(payload)

		case "winsvcaction":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				retData := a.ControlService(p.Data["name"], p.Data["action"])
				a.Logger.Debugln(retData)
				ret.Encode(retData)
				msg.Respond(resp)
			}(payload)

		case "editwinsvc":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				retData := a.EditService(p.Data["name"], p.Data["startType"])
				a.Logger.Debugln(retData)
				ret.Encode(retData)
				msg.Respond(resp)
			}(payload)

		case "runscript":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				out, err, _, _ := a.RunScript(p.Data["code"], p.Data["shell"], p.ScriptArgs, p.Timeout)
				retData := out + err
				a.Logger.Debugln(retData)
				ret.Encode(retData)
				msg.Respond(resp)
			}(payload)

		case "recover":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))

				switch p.Data["mode"] {
				case "mesh":
					a.Logger.Debugln("Recovering mesh")
					a.RecoverMesh()
				case "salt":
					a.Logger.Debugln("Recovering salt")
					a.RecoverSalt()
				case "tacagent":
					a.Logger.Debugln("Recovering tactical agent")
					a.RecoverTacticalAgent()
				case "checkrunner":
					a.Logger.Debugln("Recovering checkrunner")
					a.RecoverCheckRunner()
				}

				ret.Encode("ok")
				msg.Respond(resp)
			}(payload)

		case "softwarelist":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				sw := a.GetInstalledSoftware()
				a.Logger.Debugln(sw)
				ret.Encode(sw)
				msg.Respond(resp)
			}()

		case "rebootnow":
			go func() {
				a.Logger.Debugln("Scheduling immediate reboot")
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				ret.Encode("ok")
				msg.Respond(resp)
				_, _ = CMD("shutdown.exe", []string{"/r", "/t", "5", "/f"}, 15, false)
			}()

		case "sysinfo":
			go func() {
				a.Logger.Debugln("Getting sysinfo with WMI")
				a.GetWMI()
			}()

		case "runchecks":
			go func() {
				a.Logger.Debugln("Running checks")
				a.RunChecks()
			}()

		case "runtask":
			go func(p *NatsMsg) {
				a.Logger.Debugln("Running task")
				a.RunTask(p.TaskPK)
			}(payload)

		case "agentupdate":
			go func(p *NatsMsg) {
				a.AgentUpdate(p.Data["url"], p.Data["inno"], p.Data["version"])
			}(payload)

		case "uninstall":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				ret.Encode("ok")
				msg.Respond(resp)
				a.AgentUninstall()
				nc.Flush()
				nc.Close()
				os.Exit(0)
			}()
		}
	})
	nc.Flush()

	if err := nc.LastError(); err != nil {
		a.Logger.Errorln(err)
		return
	}

	runtime.Goexit()
}

func setupConnOptions(opts []nats.Option) []nats.Option {
	opts = append(opts, nats.ReconnectWait(time.Second*5))
	opts = append(opts, nats.RetryOnFailedConnect(true))
	opts = append(opts, nats.MaxReconnects(-1))
	return opts
}
