package agent

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	rmm "github.com/wh1te909/rmmagent/shared"
)

// WinAgentSvc tacticalagent windows nssm service
func (a *WindowsAgent) WinAgentSvc() {
	a.Logger.Infoln("Agent service started")
	a.Logger.Debugln("Sleeping for 15 seconds")
	time.Sleep(15 * time.Second)
	CMD("schtasks", []string{"/delete", "/TN", "TacticalRMM_fixmesh", "/f"}, 10, false)

	opts := a.setupNatsOptions()
	server := fmt.Sprintf("tls://%s:4222", a.SaltMaster)

	nc, err := nats.Connect(server, opts...)
	if err != nil {
		a.Logger.Errorln(err)
		os.Exit(1)
	}

	startup := []string{"hello", "osinfo", "winservices", "disks", "publicip", "software", "loggedonuser"}
	for _, s := range startup {
		a.CheckIn(nc, s)
		time.Sleep(600 * time.Millisecond)
	}
	a.SyncMeshNodeID(nc)

	checkInTicker := time.NewTicker(time.Duration(randRange(30, 90)) * time.Second)
	checkInOSTicker := time.NewTicker(5 * time.Minute)
	checkInWinSvcTicker := time.NewTicker(15 * time.Minute)
	checkInPubIPTicker := time.NewTicker(6 * time.Minute)
	checkInDisksTicker := time.NewTicker(4 * time.Minute)
	checkInLoggedUserTicker := time.NewTicker(17 * time.Minute)
	checkInSWTicker := time.NewTicker(45 * time.Minute)
	syncMeshTicker := time.NewTicker(50 * time.Minute)

	for {
		select {
		case <-checkInTicker.C:
			a.CheckIn(nc, "hello")
		case <-checkInOSTicker.C:
			a.CheckIn(nc, "osinfo")
		case <-checkInWinSvcTicker.C:
			a.CheckIn(nc, "winservices")
		case <-checkInPubIPTicker.C:
			a.CheckIn(nc, "publicip")
		case <-checkInDisksTicker.C:
			a.CheckIn(nc, "disks")
		case <-checkInLoggedUserTicker.C:
			a.CheckIn(nc, "loggedonuser")
		case <-checkInSWTicker.C:
			a.CheckIn(nc, "software")
		case <-syncMeshTicker.C:
			a.SyncMeshNodeID(nc)
		}
	}
}

func (a *WindowsAgent) CheckIn(nc *nats.Conn, mode string) {
	var payload interface{}
	var resp []byte
	ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))

	switch mode {
	case "hello":
		payload = rmm.CheckIn{
			Func:    "hello",
			Agentid: a.AgentID,
			Version: a.Version,
		}
	case "osinfo":
		plat, osinfo := a.OSInfo()
		payload = rmm.CheckInOS{
			CheckIn: rmm.CheckIn{
				Func:    "osinfo",
				Agentid: a.AgentID,
				Version: a.Version,
			},
			Hostname: a.Hostname,
			OS:       osinfo,
			Platform: plat,
			TotalRAM: a.TotalRAM(),
			BootTime: a.BootTime(),
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
	ret.Encode(payload)
	nc.PublishRequest(a.AgentID, mode, resp)
}

func randRange(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
