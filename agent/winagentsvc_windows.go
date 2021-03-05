package agent

import (
	"math/rand"
	"sync"
	"time"

	rmm "github.com/wh1te909/rmmagent/shared"
)

func (a *WindowsAgent) RunAsService() {
	var wg sync.WaitGroup
	wg.Add(1)
	go a.WinAgentSvc()
	go a.CheckRunner()
	wg.Wait()
}

// WinAgentSvc tacticalagent windows nssm service
func (a *WindowsAgent) WinAgentSvc() {
	a.Logger.Infoln("Agent service started")
	go a.GetPython(false)
	sleepDelay := randRange(14, 22)
	a.Logger.Debugf("Sleeping for %v seconds", sleepDelay)
	time.Sleep(time.Duration(sleepDelay) * time.Second)

	a.RunMigrations()
	startup := []string{"hello", "osinfo", "winservices", "disks", "publicip", "software", "loggedonuser"}
	for _, s := range startup {
		a.CheckIn(s)
		time.Sleep(time.Duration(randRange(300, 900)) * time.Millisecond)
	}
	a.SyncMeshNodeID()
	time.Sleep(1 * time.Second)
	a.CheckForRecovery()

	time.Sleep(time.Duration(randRange(2, 7)) * time.Second)
	a.CheckIn("startup")

	checkInTicker := time.NewTicker(time.Duration(randRange(40, 110)) * time.Second)
	checkInOSTicker := time.NewTicker(time.Duration(randRange(250, 450)) * time.Second)
	checkInWinSvcTicker := time.NewTicker(time.Duration(randRange(700, 1000)) * time.Second)
	checkInPubIPTicker := time.NewTicker(time.Duration(randRange(300, 500)) * time.Second)
	checkInDisksTicker := time.NewTicker(time.Duration(randRange(200, 600)) * time.Second)
	checkInLoggedUserTicker := time.NewTicker(time.Duration(randRange(850, 1400)) * time.Second)
	checkInSWTicker := time.NewTicker(time.Duration(randRange(2400, 3000)) * time.Second)
	syncMeshTicker := time.NewTicker(time.Duration(randRange(2400, 2900)) * time.Second)
	recoveryTicker := time.NewTicker(time.Duration(randRange(180, 300)) * time.Second)

	for {
		select {
		case <-checkInTicker.C:
			a.CheckIn("hello")
		case <-checkInOSTicker.C:
			a.CheckIn("osinfo")
		case <-checkInWinSvcTicker.C:
			a.CheckIn("winservices")
		case <-checkInPubIPTicker.C:
			a.CheckIn("publicip")
		case <-checkInDisksTicker.C:
			a.CheckIn("disks")
		case <-checkInLoggedUserTicker.C:
			a.CheckIn("loggedonuser")
		case <-checkInSWTicker.C:
			a.CheckIn("software")
		case <-syncMeshTicker.C:
			a.SyncMeshNodeID()
		case <-recoveryTicker.C:
			a.CheckForRecovery()
		}
	}
}

func (a *WindowsAgent) CheckIn(mode string) {
	var rerr error
	var payload interface{}

	switch mode {
	case "hello":
		payload = rmm.CheckIn{
			Func:    "hello",
			Agentid: a.AgentID,
			Version: a.Version,
		}
	case "startup":
		payload = rmm.CheckIn{
			Func:    "startup",
			Agentid: a.AgentID,
			Version: a.Version,
		}
	case "osinfo":
		plat, osinfo := a.OSInfo()
		reboot, err := a.SystemRebootRequired()
		if err != nil {
			reboot = false
		}
		payload = rmm.CheckInOS{
			CheckIn: rmm.CheckIn{
				Func:    "osinfo",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			Hostname:     a.Hostname,
			OS:           osinfo,
			Platform:     plat,
			TotalRAM:     a.TotalRAM(),
			BootTime:     a.BootTime(),
			RebootNeeded: reboot,
		}
	case "winservices":
		payload = rmm.CheckInWinServices{
			CheckIn: rmm.CheckIn{
				Func:    "winservices",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			Services: a.GetServices(),
		}
	case "publicip":
		payload = rmm.CheckInPublicIP{
			CheckIn: rmm.CheckIn{
				Func:    "publicip",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			PublicIP: a.PublicIP(),
		}
	case "disks":
		payload = rmm.CheckInDisk{
			CheckIn: rmm.CheckIn{
				Func:    "disks",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			Disks: a.GetDisks(),
		}
	case "loggedonuser":
		payload = rmm.CheckInLoggedUser{
			CheckIn: rmm.CheckIn{
				Func:    "loggedonuser",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			Username: a.LoggedOnUser(),
		}
	case "software":
		payload = rmm.CheckInSW{
			CheckIn: rmm.CheckIn{
				Func:    "software",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			InstalledSW: a.GetInstalledSoftware(),
		}
	}

	url := "/api/v3/checkin/"

	if mode == "hello" {
		_, rerr = a.rClient.R().SetBody(payload).Patch(url)
	} else if mode == "startup" {
		_, rerr = a.rClient.R().SetBody(payload).Post(url)
	} else {
		_, rerr = a.rClient.R().SetBody(payload).Put(url)
	}

	if rerr != nil {
		a.Logger.Debugln("Checkin:", rerr)
	}
}

func randRange(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
