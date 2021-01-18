package agent

import (
	"encoding/json"
	"fmt"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	rmm "github.com/wh1te909/rmmagent/shared"
)

type WindowsUpdate struct {
	PatchID int64  `json:"id"`
	KB      string `json:"kb"`
	GUID    string `json:"guid"`
}

type WindowsUpdates []WindowsUpdate

type SaltDownloadRet struct {
	Updates interface{} `json:"Updates"`
	Message string      `json:"Message"`
	Success bool        `json:"Success"`
}

type SaltInstallRet struct {
	Updates     interface{} `json:"Updates"`
	Message     string      `json:"Message"`
	Success     bool        `json:"Success"`
	NeedsReboot bool        `json:"NeedsReboot"`
}

type SaltUpdateOutput struct {
	SaltDownload SaltDownloadRet `json:"Download"`
	SaltInstall  SaltInstallRet  `json:"Install"`
}

type LocalSaltUpdate struct {
	Local SaltUpdateOutput `json:"local"`
}

func (a *WindowsAgent) GetWinUpdates(nc *nats.Conn) {
	updates, err := WUAUpdates("IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0")
	if err != nil {
		a.Logger.Errorln(err)
		return
	}

	payload := rmm.WinUpdateResult{AgentID: a.AgentID, Updates: updates}
	var resp []byte
	ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
	ret.Encode(payload)
	nc.PublishRequest(a.AgentID, "getwinupdates", resp)
}

func (a *WindowsAgent) InstallPatches() {
	data := WindowsUpdates{}

	r := APIRequest{
		URL:       fmt.Sprintf("%s/api/v3/%s/winupdater/", a.Server, a.AgentID),
		Method:    "GET",
		Headers:   a.Headers,
		Timeout:   30,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	r1, err := r.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	if r1.IsError() {
		a.Logger.Debugln("Install Patches:", r1.String())
		return
	}

	if err := json.Unmarshal(r1.Body(), &data); err != nil {
		a.Logger.Debugln(err)
		return
	}

	// no patches
	if len(data) == 0 {
		return
	}

	saltdata := LocalSaltUpdate{}

	url := fmt.Sprintf("%s/api/v3/winupdater/", a.Server)
	for _, patch := range data {
		out, err := a.LocalSaltCall("win_wua.get", []string{patch.KB, "download=True", "install=True"}, 7200)
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}

		if err := json.Unmarshal(out, &saltdata); err != nil {
			a.Logger.Debugln(err)
			continue
		}

		a.Logger.Infoln(saltdata)
		payload := map[string]string{"agent_id": a.AgentID, "kb": patch.KB}

		if saltdata.Local.SaltInstall.Updates == "Nothing to install" {
			payload["results"] = "alreadyinstalled"
		} else {
			if saltdata.Local.SaltInstall.Success {
				payload["results"] = "success"
			} else {
				payload["results"] = "failed"
			}
		}

		r := APIRequest{
			URL:       url,
			Headers:   a.Headers,
			Method:    "PATCH",
			Payload:   payload,
			Timeout:   30,
			LocalCert: a.DB.Cert,
			Debug:     a.Debug,
		}

		_, rerr := r.MakeRequest()
		if rerr != nil {
			a.Logger.Debugln(rerr)
		}
	}

	type LocalSaltNeedsReboot struct {
		Local bool `json:"local"`
	}

	out, err := a.LocalSaltCall("win_wua.get_needs_reboot", []string{}, 60)
	if err != nil {
		return
	}

	needsReboot := LocalSaltNeedsReboot{}
	if err := json.Unmarshal(out, &needsReboot); err != nil {
		return
	}

	r.URL = url
	r.Method = "POST"
	r.Payload = map[string]interface{}{
		"agent_id": a.AgentID,
		"reboot":   needsReboot.Local,
	}

	_, rerr := r.MakeRequest()
	if rerr != nil {
		a.Logger.Debugln(rerr)
	}

}
