package agent

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

//HelloPatch patch
type HelloPatch struct {
	Agentid  string  `json:"agent_id"`
	Hostname string  `json:"hostname"`
	OS       string  `json:"operating_system"`
	TotalRAM float64 `json:"total_ram"`
	Platform string  `json:"plat"`
	PublicIP string  `json:"public_ip"`
	Disks    []Disk  `json:"disks"`
	Username string  `json:"logged_in_username"`
	Version  string  `json:"version"`
	BootTime int64   `json:"boot_time"`
}

// WinAgentSvc tacticalagent windows nssm service
func (a *WindowsAgent) WinAgentSvc() {
	a.Logger.Infoln("Agent service started")
	a.InstallRPCService()

	a.Logger.Debugln("Sleeping for 20 seconds")
	time.Sleep(20 * time.Second)
	CMD("schtasks", []string{"/Change", "/TN", "TacticalRMM_fixmesh", "/ENABLE"}, 10, false)
	CMD("schtasks", []string{"/delete", "/TN", "TacticalRMM_sync", "/f"}, 10, false)

	err := a.AgentStartup()
	if err != nil {
		a.Logger.Debugln("AgentStartup", err)
	}

	time.Sleep(2 * time.Second)
	sleep := randRange(30, 90)
	for {
		err = a.CheckIn()
		if err != nil {
			a.Logger.Debugln("CheckIn:", err)
		}
		a.Logger.Debugln("CheckIn sleeping for", sleep)
		time.Sleep(time.Duration(sleep) * time.Second)
	}
}

func (a *WindowsAgent) CheckIn() error {

	var data map[string]interface{}
	url := a.Server + "/api/v3/hello/"

	plat, osinfo := OSInfo()
	payload := HelloPatch{
		Agentid:  a.AgentID,
		Hostname: a.Hostname,
		OS:       osinfo,
		TotalRAM: TotalRAM(),
		Platform: plat,
		PublicIP: PublicIP(),
		Disks:    a.GetDisks(),
		Username: LoggedOnUser(),
		Version:  a.Version,
		BootTime: BootTime(),
	}

	req := APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Method:    "PATCH",
		Payload:   payload,
		Timeout:   20,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}
	a.Logger.Debugln(req)

	r, err := req.MakeRequest()
	if err != nil {
		return err
	}

	if r.IsError() {
		return fmt.Errorf("bad hello response, code: %d", r.StatusCode())
	}

	ret := DjangoStringResp(r.String())
	a.Logger.Debugln("Django ret:", ret)
	if len(ret) > 0 && ret != "ok" {
		if err := json.Unmarshal(r.Body(), &data); err != nil {
			return err
		}
		// recovery
		if action, ok := data["recovery"].(string); ok {
			switch action {
			case "salt":
				a.RecoverSalt()
			case "mesh":
				a.RecoverMesh()
			case "rpc":
				a.RecoverRPC()
			case "checkrunner":
				a.RecoverCheckRunner()
			case "command":
				if cmd, ok := data["cmd"].(string); ok {
					a.RecoverCMD(cmd)
				}
			}
		}
		// agent update
		if version, ok := data["version"].(string); ok {
			if inno, iok := data["inno"].(string); iok {
				if url, uok := data["url"].(string); uok {
					a.AgentUpdate(url, inno, version)
				}
			}
		}
	}
	return nil
}

func (a *WindowsAgent) AgentStartup() error {
	url := a.Server + "/api/v3/hello/"
	a.Logger.Debugln(url)

	payload := struct {
		Agentid  string `json:"agent_id"`
		Hostname string `json:"hostname"`
	}{Agentid: a.AgentID, Hostname: a.Hostname}
	a.Logger.Debugln(payload)

	req := APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Method:    "POST",
		Payload:   payload,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}
	a.Logger.Debugln(req)

	r, err := req.MakeRequest()
	if err != nil {
		return err
	}

	if r.IsError() {
		return fmt.Errorf("bad startup response, code: %d", r.StatusCode())
	}

	a.Logger.Debugln(r.String())
	return nil
}

func randRange(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
