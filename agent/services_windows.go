package agent

import (
	"time"

	rmm "github.com/wh1te909/rmmagent/shared"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// WinSvcResp for sending service control status back to the rmm
type WinSvcResp struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errormsg"`
}

func GetServiceStatus(name string) (string, error) {
	conn, err := mgr.Connect()
	if err != nil {
		return "n/a", err
	}
	defer conn.Disconnect()

	srv, err := conn.OpenService(name)
	if err != nil {
		return "n/a", err
	}
	defer srv.Close()

	q, err := srv.Query()
	if err != nil {
		return "n/a", err
	}

	return serviceStatusText(uint32(q.State)), nil
}

func (a *WindowsAgent) ControlService(name, action string) WinSvcResp {
	conn, err := mgr.Connect()
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	defer conn.Disconnect()

	srv, err := conn.OpenService(name)
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	defer srv.Close()

	var status svc.Status
	switch action {

	case "stop":
		status, err = srv.Control(svc.Stop)
		if err != nil {
			return WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		timeout := time.Now().Add(30 * time.Second)
		for status.State != svc.Stopped {
			if timeout.Before(time.Now()) {
				return WinSvcResp{Success: false, ErrorMsg: "Timed out waiting for service to stop"}
			}
			time.Sleep(500 * time.Millisecond)
			status, err = srv.Query()
			if err != nil {
				return WinSvcResp{Success: false, ErrorMsg: err.Error()}
			}
		}
		return WinSvcResp{Success: true, ErrorMsg: ""}

	case "start":
		err := srv.Start()
		if err != nil {
			return WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return WinSvcResp{Success: true, ErrorMsg: ""}
	}

	return WinSvcResp{Success: false, ErrorMsg: "Something went wrong"}
}

func (a *WindowsAgent) EditService(name, startupType string) WinSvcResp {
	conn, err := mgr.Connect()
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	defer conn.Disconnect()

	srv, err := conn.OpenService(name)
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	defer srv.Close()

	conf, err := srv.Config()
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}

	var startType uint32
	switch startupType {
	case "auto":
		startType = 2
	case "autodelay":
		startType = 2
	case "manual":
		startType = 3
	case "disabled":
		startType = 4
	default:
		return WinSvcResp{Success: false, ErrorMsg: "Unknown startup type provided"}
	}

	conf.StartType = startType
	if startupType == "autodelay" {
		conf.DelayedAutoStart = true
	} else if startupType == "auto" {
		conf.DelayedAutoStart = false
	}

	err = srv.UpdateConfig(conf)
	if err != nil {
		return WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	return WinSvcResp{Success: true, ErrorMsg: ""}
}

func (a *WindowsAgent) GetServiceDetail(name string) rmm.WindowsService {
	ret := rmm.WindowsService{}

	conn, err := mgr.Connect()
	if err != nil {
		a.Logger.Errorln(err)
		return ret
	}
	defer conn.Disconnect()

	srv, err := conn.OpenService(name)
	if err != nil {
		a.Logger.Errorln(err)
		return ret
	}
	defer srv.Close()

	q, err := srv.Query()
	if err != nil {
		a.Logger.Errorln(err)
		return ret
	}

	conf, err := srv.Config()
	if err != nil {
		a.Logger.Errorln(err)
		return ret
	}

	ret.BinPath = conf.BinaryPathName
	ret.Description = conf.Description
	ret.DisplayName = conf.DisplayName
	ret.Name = name
	ret.PID = q.ProcessId
	ret.StartType = serviceStartType(uint32(conf.StartType))
	ret.Status = serviceStatusText(uint32(q.State))
	ret.Username = conf.ServiceStartName
	ret.DelayedAutoStart = conf.DelayedAutoStart
	return ret
}

// GetServices returns a list of windows services
func (a *WindowsAgent) GetServices() []rmm.WindowsService {
	ret := make([]rmm.WindowsService, 0)

	conn, err := mgr.Connect()
	if err != nil {
		a.Logger.Debugln(err)
		return ret
	}
	defer conn.Disconnect()

	svcs, err := conn.ListServices()

	if err != nil {
		a.Logger.Debugln(err)
		return ret
	}

	for _, s := range svcs {
		srv, err := conn.OpenService(s)
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}
		defer srv.Close()

		q, err := srv.Query()
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}

		conf, err := srv.Config()
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}

		ret = append(ret, rmm.WindowsService{
			Name:             s,
			Status:           serviceStatusText(uint32(q.State)),
			DisplayName:      conf.DisplayName,
			BinPath:          conf.BinaryPathName,
			Description:      conf.Description,
			Username:         conf.ServiceStartName,
			PID:              q.ProcessId,
			StartType:        serviceStartType(uint32(conf.StartType)),
			DelayedAutoStart: conf.DelayedAutoStart,
		})
	}
	return ret
}

// WaitForService will wait for a service to be in X state for X retries
func WaitForService(name string, status string, retries int) {
	attempts := 0
	for {
		stat, err := GetServiceStatus(name)
		if err != nil {
			attempts++
			time.Sleep(5 * time.Second)
		} else {
			if stat != status {
				attempts++
				time.Sleep(5 * time.Second)
			} else {
				attempts = 0
			}
		}
		if attempts == 0 || attempts >= retries {
			break
		}
	}
}

func serviceExists(name string) bool {
	conn, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer conn.Disconnect()

	srv, err := conn.OpenService(name)
	if err != nil {
		return false
	}
	defer srv.Close()

	return true
}

// https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontrollerstatus?view=dotnet-plat-ext-3.1
func serviceStatusText(num uint32) string {
	switch num {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	default:
		return "unknown"
	}
}

// https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicestartmode?view=dotnet-plat-ext-3.1
func serviceStartType(num uint32) string {
	switch num {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Automatic"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return "Unknown"
	}
}
