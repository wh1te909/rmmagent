package agent

import (
	"encoding/json"
	"math/rand"
	"time"
)

//CheckInPut patch
type CheckInPut struct {
	Agentid  string           `json:"agent_id"`
	Hostname string           `json:"hostname"`
	OS       string           `json:"operating_system"`
	TotalRAM float64          `json:"total_ram"`
	Platform string           `json:"plat"`
	PublicIP string           `json:"public_ip"`
	Disks    []Disk           `json:"disks"`
	Services []WindowsService `json:"services"`
	Username string           `json:"logged_in_username"`
	Version  string           `json:"version"`
	BootTime int64            `json:"boot_time"`
}

// WinAgentSvc tacticalagent windows nssm service
func (a *WindowsAgent) WinAgentSvc() {
	a.Logger.Infoln("Agent service started")

	a.Logger.Debugln("Sleeping for 20 seconds")
	time.Sleep(20 * time.Second)
	CMD("schtasks", []string{"/Change", "/TN", "TacticalRMM_fixmesh", "/ENABLE"}, 10, false)

	a.AgentStartup()

	time.Sleep(2 * time.Second)
	a.CheckIn()

	time.Sleep(2 * time.Second)
	a.SysInfo("all")

	checkInSleep := randRange(45, 110)
	a.Logger.Debugln("CheckIn interval:", checkInSleep)

	checkInTicker := time.NewTicker(time.Duration(checkInSleep) * time.Second)
	for range checkInTicker.C {
		a.CheckIn()
	}
}

func (a *WindowsAgent) SysInfo(mode string) {
	var payload interface{}
	a.Logger.Debugln("SysInfo start:", mode)
	url := a.Server + "/api/v3/checkin/"

	switch mode {
	case "all":
		plat, osinfo := a.OSInfo()
		payload = CheckInPut{
			Services: a.GetServices(),
			Agentid:  a.AgentID,
			Hostname: a.Hostname,
			OS:       osinfo,
			TotalRAM: a.TotalRAM(),
			Platform: plat,
			PublicIP: a.PublicIP(),
			Disks:    a.GetDisks(),
			Username: a.LoggedOnUser(),
			Version:  a.Version,
			BootTime: a.BootTime(),
		}
	case "publicip":
		payload = struct {
			PublicIP string `json:"public_ip"`
			Agentid  string `json:"agent_id"`
		}{a.PublicIP(), a.AgentID}
	case "basic":
		plat, osinfo := a.OSInfo()
		payload = struct {
			Hostname string  `json:"hostname"`
			OS       string  `json:"operating_system"`
			TotalRAM float64 `json:"total_ram"`
			Platform string  `json:"plat"`
			BootTime int64   `json:"boot_time"`
			Agentid  string  `json:"agent_id"`
		}{a.Hostname, osinfo, a.TotalRAM(), plat, a.BootTime(), a.AgentID}
	case "disks":
		payload = struct {
			Disks   []Disk `json:"disks"`
			Agentid string `json:"agent_id"`
		}{a.GetDisks(), a.AgentID}
	case "winsvcs":
		payload = struct {
			Services []WindowsService `json:"services"`
			Agentid  string           `json:"agent_id"`
		}{a.GetServices(), a.AgentID}
	case "loggeduser":
		payload = struct {
			Username string `json:"logged_in_username"`
			Agentid  string `json:"agent_id"`
		}{a.LoggedOnUser(), a.AgentID}
	default:
		return
	}

	req := APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Method:    "PUT",
		Payload:   payload,
		Timeout:   20,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}
	a.Logger.Debugln(req)

	_, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
	}
	a.Logger.Debugln("SysInfo end:", mode)
}

func (a *WindowsAgent) CheckIn() {
	a.Logger.Debugln("CheckIn start")
	var data map[string]interface{}
	url := a.Server + "/api/v3/checkin/"

	payload := struct {
		Agentid string `json:"agent_id"`
		Version string `json:"version"`
	}{a.AgentID, a.Version}

	req := APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Method:    "PATCH",
		Payload:   payload,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}
	a.Logger.Debugln(req)

	r, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln("CheckIn error:", err)
		return
	}

	if r.IsError() {
		a.Logger.Debugln("CheckIn response:", r.StatusCode())
		return
	}

	ret := DjangoStringResp(r.String())
	a.Logger.Debugln("Django ret:", ret)
	if len(ret) > 0 && ret != "ok" {
		if err := json.Unmarshal(r.Body(), &data); err != nil {
			a.Logger.Debugln("CheckIn unmarshal error:", err)
			return
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
	a.Logger.Debugln("CheckIn end")
}

func (a *WindowsAgent) AgentStartup() {
	url := a.Server + "/api/v3/checkin/"
	a.Logger.Debugln(url)

	payload := struct {
		Agentid  string `json:"agent_id"`
		Hostname string `json:"hostname"`
	}{a.AgentID, a.Hostname}
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
		a.Logger.Debugln("Startup error:", err)
		return
	}

	if r.IsError() {
		a.Logger.Debugln("Startup response:", r.StatusCode())
	}
	a.Logger.Debugln("Startup:", r.String())
}

func randRange(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
