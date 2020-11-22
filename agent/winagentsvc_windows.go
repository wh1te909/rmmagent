package agent

import (
	"encoding/json"
	"math/rand"
	"time"
)

//HelloPost post
type HelloPost struct {
	Agentid     string  `json:"agent_id"`
	Hostname    string  `json:"hostname"`
	OS          string  `json:"operating_system"`
	TotalRAM    float64 `json:"total_ram"`
	Platform    string  `json:"plat"`
	Version     string  `json:"version"`
	BootTime    int64   `json:"boot_time"`
	SaltVersion string  `json:"salt_ver"`
}

//HelloPatch patch
type HelloPatch struct {
	Agentid     string           `json:"agent_id"`
	Hostname    string           `json:"hostname"`
	OS          string           `json:"operating_system"`
	TotalRAM    float64          `json:"total_ram"`
	Platform    string           `json:"plat"`
	Services    []WindowsService `json:"services"`
	PublicIP    string           `json:"public_ip"`
	Disks       []Disk           `json:"disks"`
	Username    string           `json:"logged_in_username"`
	Version     string           `json:"version"`
	BootTime    int64            `json:"boot_time"`
	SaltVersion string           `json:"salt_ver"`
}

// WinAgentSvc tacticalagent windows nssm service
func (a *WindowsAgent) WinAgentSvc() {
	a.Logger.Infoln("Agent service started")
	a.InstallRPCService()
	a.CleanupPythonAgent()
	var data map[string]interface{}
	var sleep int

	time.Sleep(20 * time.Second)
	url := a.Server + "/api/v3/hello/"
	req := &APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	plat, osinfo := OSInfo()
	saltVer := a.GetProgramVersion("salt minion")

	postPayload := HelloPost{
		Agentid:     a.AgentID,
		Hostname:    a.Hostname,
		OS:          osinfo,
		TotalRAM:    TotalRAM(),
		Platform:    plat,
		Version:     a.Version,
		BootTime:    BootTime(),
		SaltVersion: saltVer,
	}

	req.Method = "POST"
	req.Payload = postPayload
	a.Logger.Debugln(req)

	_, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
	}

	time.Sleep(3 * time.Second)

	for {
		patchPayload := HelloPatch{
			Agentid:     a.AgentID,
			Hostname:    a.Hostname,
			OS:          osinfo,
			TotalRAM:    TotalRAM(),
			Platform:    plat,
			Services:    a.GetServices(),
			PublicIP:    PublicIP(),
			Disks:       a.GetDisks(),
			Username:    LoggedOnUser(),
			Version:     a.Version,
			BootTime:    BootTime(),
			SaltVersion: saltVer,
		}

		req.Method = "PATCH"
		req.Payload = patchPayload
		a.Logger.Debugln(req)

		r, err := req.MakeRequest()
		if err != nil {
			a.Logger.Debugln(err)
		} else {
			ret := DjangoStringResp(r.String())
			if len(ret) > 0 && ret != "ok" {
				if err := json.Unmarshal(r.Body(), &data); err != nil {
					a.Logger.Debugln(err)
				} else {
					// recovery
					if action, ok := data["recovery"].(string); ok {
						switch action {
						case "salt":
							go a.RecoverSalt()
						case "mesh":
							go a.RecoverMesh()
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
			}
		}
		sleep = randRange(30, 120)
		time.Sleep(time.Duration(sleep) * time.Second)
	}
}

func randRange(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
