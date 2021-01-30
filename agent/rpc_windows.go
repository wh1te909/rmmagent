package agent

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

type NatsMsg struct {
	Func             string            `json:"func"`
	Timeout          int               `json:"timeout"`
	Data             map[string]string `json:"payload"`
	ScriptArgs       []string          `json:"script_args"`
	ProcPID          int32             `json:"procpid"`
	TaskPK           int               `json:"taskpk"`
	ScheduledTask    SchedTask         `json:"schedtaskpayload"`
	RecoveryCommand  string            `json:"recoverycommand"`
	UpdateGUIDs      []string          `json:"guids"`
	ChocoProgName    string            `json:"choco_prog_name"`
	ChocoProgVersion string            `json:"choco_prog_ver"`
}

var (
	agentUpdateLocker      uint32
	getWinUpdateLocker     uint32
	installWinUpdateLocker uint32
)

func (a *WindowsAgent) RunRPC() {
	a.Logger.Infoln("RPC service started")
	opts := a.setupNatsOptions()
	server := fmt.Sprintf("tls://%s:4222", a.ApiURL)
	nc, err := nats.Connect(server, opts...)
	if err != nil {
		a.Logger.Fatalln(err)
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
				var retData string
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				stdout, stderr, _, err := a.RunScript(p.Data["code"], p.Data["shell"], p.ScriptArgs, p.Timeout)
				if err != nil {
					a.Logger.Debugln(err)
					retData = err.Error()
				} else {
					retData = stdout + stderr
				}
				a.Logger.Debugln(retData)
				ret.Encode(retData)
				msg.Respond(resp)
			}(payload)

		case "runscriptfull":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				start := time.Now()
				out, err, retcode, _ := a.RunScript(p.Data["code"], p.Data["shell"], p.ScriptArgs, p.Timeout)
				retData := struct {
					Stdout   string  `json:"stdout"`
					Stderr   string  `json:"stderr"`
					Retcode  int     `json:"retcode"`
					ExecTime float64 `json:"execution_time"`
				}{out, err, retcode, time.Since(start).Seconds()}
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
					a.RecoverMesh(nc)
				case "salt":
					a.Logger.Debugln("Recovering salt")
					a.RecoverSalt()
				case "tacagent":
					a.Logger.Debugln("Recovering tactical agent")
					a.RecoverTacticalAgent()
				}

				ret.Encode("ok")
				msg.Respond(resp)
			}(payload)

		case "recoverycmd":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				ret.Encode("ok")
				msg.Respond(resp)
				a.RecoverCMD(p.RecoveryCommand)
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
		case "needsreboot":
			go func() {
				a.Logger.Debugln("Checking if reboot needed")
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				out, err := a.SystemRebootRequired()
				if err == nil {
					a.Logger.Debugln("Reboot needed:", out)
					ret.Encode(out)
				} else {
					a.Logger.Debugln("Error checking if reboot needed:", err)
					ret.Encode(false)
				}
				msg.Respond(resp)
			}()
		case "sysinfo":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				a.Logger.Debugln("Getting sysinfo with WMI")
				modes := []string{"osinfo", "publicip", "disks"}
				for _, m := range modes {
					a.CheckIn(nc, m)
					time.Sleep(200 * time.Millisecond)
				}
				a.GetWMI()
				ret.Encode("ok")
				msg.Respond(resp)
			}()
		case "sync":
			go func() {
				a.Logger.Debugln("Sending sysinfo and software")
				a.Sync()
			}()
		case "wmi":
			go func() {
				a.Logger.Debugln("Sending WMI")
				a.GetWMI()
			}()
		case "cpuloadavg":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				a.Logger.Debugln("Getting CPU Load Avg")
				loadAvg := a.GetCPULoadAvg()
				a.Logger.Debugln("CPU Load Avg:", loadAvg)
				ret.Encode(loadAvg)
				msg.Respond(resp)
			}()
		case "runchecks":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				if a.ChecksRunning() {
					ret.Encode("busy")
					msg.Respond(resp)
					a.Logger.Debugln("Checks are already running, please wait")
				} else {
					ret.Encode("ok")
					msg.Respond(resp)
					a.Logger.Debugln("Running checks")
					_, checkerr := CMD(a.EXE, []string{"-m", "runchecks"}, 600, false)
					if checkerr != nil {
						a.Logger.Errorln("RPC RunChecks", checkerr)
					}
				}
			}()
		case "runtask":
			go func(p *NatsMsg) {
				a.Logger.Debugln("Running task")
				a.RunTask(p.TaskPK)
			}(payload)

		case "publicip":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				ret.Encode(a.PublicIP())
				msg.Respond(resp)
			}()
		case "installpython":
			go a.GetPython(true)
		case "removesalt":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				err := a.RemoveSalt()
				if err != nil {
					ret.Encode(err.Error())
				} else {
					ret.Encode("ok")
				}
				msg.Respond(resp)
			}()
		case "installchoco":
			go a.InstallChoco(nc)
		case "installwithchoco":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				msg.Respond(resp)
				out, _ := a.InstallWithChoco(p.ChocoProgName, p.ChocoProgVersion)
				ret.Encode(out)
				msg.Respond(resp)
			}(payload)
		case "getwinupdates":
			go func() {
				if !atomic.CompareAndSwapUint32(&getWinUpdateLocker, 0, 1) {
					a.Logger.Debugln("Already checking for windows updates")
				} else {
					a.Logger.Debugln("Checking for windows updates")
					defer atomic.StoreUint32(&getWinUpdateLocker, 0)
					a.GetWinUpdates(nc)
				}
			}()
		case "installwinupdates":
			go func(p *NatsMsg) {
				if !atomic.CompareAndSwapUint32(&installWinUpdateLocker, 0, 1) {
					a.Logger.Debugln("Already installing windows updates")
				} else {
					a.Logger.Debugln("Installing windows updates", p.UpdateGUIDs)
					defer atomic.StoreUint32(&installWinUpdateLocker, 0)
					a.InstallUpdates(nc, p.UpdateGUIDs)
				}
			}(payload)
		case "agentupdate":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				if !atomic.CompareAndSwapUint32(&agentUpdateLocker, 0, 1) {
					a.Logger.Debugln("Agent update already running")
					ret.Encode("updaterunning")
					msg.Respond(resp)
				} else {
					ret.Encode("ok")
					msg.Respond(resp)
					a.AgentUpdate(p.Data["url"], p.Data["inno"], p.Data["version"])
					atomic.StoreUint32(&agentUpdateLocker, 0)
					nc.Flush()
					nc.Close()
					os.Exit(0)
				}
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
		os.Exit(1)
	}

	runtime.Goexit()
}
