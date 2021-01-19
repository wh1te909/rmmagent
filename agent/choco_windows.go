package agent

import (
	"time"

	"github.com/go-resty/resty/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	rmm "github.com/wh1te909/rmmagent/shared"
)

func (a *WindowsAgent) InstallChoco(nc *nats.Conn) {
	var resp []byte
	var result rmm.ChocoInstalled
	result.AgentID = a.AgentID
	result.Installed = false
	ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))

	rClient := resty.New()
	rClient.SetTimeout(30 * time.Second)

	r, err := rClient.R().Get("https://chocolatey.org/install.ps1")
	if err != nil {
		ret.Encode(result)
		nc.PublishRequest(a.AgentID, "chocoinstall", resp)
		return
	}
	if r.IsError() {
		ret.Encode(result)
		nc.PublishRequest(a.AgentID, "chocoinstall", resp)
		return
	}

	_, _, exitcode, err := a.RunScript(string(r.Body()), "powershell", []string{}, 900)
	if err != nil {
		ret.Encode(result)
		nc.PublishRequest(a.AgentID, "chocoinstall", resp)
		return
	}

	if exitcode != 0 {
		ret.Encode(result)
		nc.PublishRequest(a.AgentID, "chocoinstall", resp)
		return
	}

	result.Installed = true
	ret.Encode(result)
	nc.PublishRequest(a.AgentID, "chocoinstall", resp)
}

func (a *WindowsAgent) InstallWithChoco(name, version string) (string, error) {
	out, err := CMD("choco.exe", []string{"install", name, "--version", version, "--yes"}, 900, false)
	if err != nil {
		a.Logger.Errorln(err)
		return err.Error(), err
	}
	if out[1] != "" {
		return out[1], nil
	}
	return out[0], nil
}
