package agent

import (
	"fmt"
	"runtime"
	"strconv"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

type NatsMsg struct {
	Func    string            `json:"func"`
	Timeout int               `json:"timeout"`
	Data    map[string]string `json:"payload"`
}

func (a *WindowsAgent) RunRPC() {
	opts := []nats.Option{nats.Name("TacticalRMM"), nats.UserInfo(a.AgentID, a.Token)}
	opts = setupConnOptions(opts)

	server := fmt.Sprintf("tls://%s:4222", a.SaltMaster)
	nc, err := nats.Connect(server, opts...)
	if err != nil {
		fmt.Println(err)
	}

	nc.Subscribe(a.AgentID, func(msg *nats.Msg) {

		var payload *NatsMsg
		var mh codec.MsgpackHandle
		mh.RawToString = true

		dec := codec.NewDecoderBytes(msg.Data, &mh)
		if err := dec.Decode(&payload); err != nil {
			fmt.Println(err)
			return
		}

		switch payload.Func {
		case "ping":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				ret.Encode("pong")
				msg.Respond(resp)
			}()

		case "eventlog":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				logName := p.Data["logname"]
				days, _ := strconv.Atoi(p.Data["days"])
				evtLog := a.GetEventLog(logName, days)
				ret.Encode(evtLog)
				msg.Respond(resp)
			}(payload)

		case "procs":
			go func() {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				procs := a.GetProcsRPC()
				ret.Encode(procs)
				msg.Respond(resp)
			}()

		case "rawcmd":
			go func(p *NatsMsg) {
				var resp []byte
				ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
				command := p.Data["command"]
				shell := p.Data["shell"]
				out, _ := CMDShell(shell, []string{}, command, payload.Timeout, false)

				if out[1] != "" {
					ret.Encode(out[1])
				} else {
					ret.Encode(out[0])
				}

				msg.Respond(resp)
			}(payload)
		}
	})
	nc.Flush()

	if err := nc.LastError(); err != nil {
		fmt.Println(err)
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
