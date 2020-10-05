// Package agent todo change this
package agent

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	ps "github.com/elastic/go-sysinfo"
	_ "github.com/mattn/go-sqlite3"
	svc "github.com/shirou/gopsutil/winservices"
	"github.com/sirupsen/logrus"
)

// WindowsAgent struct
type WindowsAgent struct {
	DB
	Host
	ProgramDir    string
	SystemDrive   string
	SaltCall      string
	Nssm          string
	SaltMinion    string
	SaltInstaller string
	MeshInstaller string
	Headers       map[string]string
	Logger        *logrus.Logger
	Version       string
}

// New __init__
func New(logger *logrus.Logger, version string) *WindowsAgent {
	host, _ := ps.Host()
	info := host.Info()
	pd := filepath.Join(os.Getenv("ProgramFiles"), "TacticalAgent")
	dbFile := filepath.Join(pd, "agentdb.db")
	sd := os.Getenv("SystemDrive")
	sc := filepath.Join(sd, "\\salt\\salt-call.bat")
	nssm, mesh, saltexe, saltinstaller := ArchInfo(pd)
	db := LoadDB(dbFile, logger)

	headers := make(map[string]string)
	if len(db.Token) > 0 {
		headers["Content-Type"] = "application/json"
		headers["Authorization"] = fmt.Sprintf("Token %s", db.Token)
	}

	return &WindowsAgent{
		DB: DB{
			db.Server,
			db.AgentID,
			db.MeshNodeID,
			db.Token,
			db.AgentPK,
			db.SaltMaster,
			db.SaltID,
			db.Cert,
		},
		Host: Host{
			Hostname: info.Hostname,
			Arch:     info.Architecture,
			Timezone: info.Timezone,
		},
		ProgramDir:    pd,
		SystemDrive:   sd,
		SaltCall:      sc,
		Nssm:          nssm,
		SaltMinion:    saltexe,
		SaltInstaller: saltinstaller,
		MeshInstaller: mesh,
		Headers:       headers,
		Logger:        logger,
		Version:       version,
	}

}

// LoadDB loads database info called during agent init
func LoadDB(file string, logger *logrus.Logger) *DB {
	if !FileExists(file) {
		return &DB{}
	}

	db, err := sql.Open("sqlite3", file)
	if err != nil {
		logger.Fatalln(err)
	}
	defer db.Close()

	rows, err := db.
		Query("select server, agentid, mesh_node_id, token, agentpk, salt_master, salt_id, cert from agentstorage")
	if err != nil {
		logger.Fatalln(err)
	}
	defer rows.Close()

	var (
		server     string
		agentid    string
		meshid     string
		token      string
		pk         int32
		saltmaster string
		saltid     string
		cert       *string
	)
	for rows.Next() {
		err = rows.
			Scan(&server, &agentid, &meshid, &token, &pk, &saltmaster, &saltid, &cert)
		if err != nil {
			logger.Fatalln(err)
		}
	}

	var ret string
	if cert != nil {
		ret = *cert
	}

	err = rows.Err()
	if err != nil {
		logger.Fatalln(err)
	}

	return &DB{server, agentid, meshid, token, pk, saltmaster, saltid, ret}
}

// ArchInfo returns arch specific filenames and urls
func ArchInfo(programDir string) (nssm, mesh, saltexe, saltinstaller string) {
	baseURL := "https://github.com/wh1te909/winagent/raw/master/bin/"
	switch runtime.GOARCH {
	case "amd64":
		nssm = filepath.Join(programDir, "nssm.exe")
		mesh = "meshagent.exe"
		saltexe = baseURL + "salt-minion-setup.exe"
		saltinstaller = "salt-minion-setup.exe"
	case "386":
		nssm = filepath.Join(programDir, "nssm-x86.exe")
		mesh = "meshagent-x86.exe"
		saltexe = baseURL + "salt-minion-setup-x86.exe"
		saltinstaller = "salt-minion-setup-x86.exe"
	}
	return
}

// OSInfo returns os names formatted
func OSInfo() (plat, osFullName string) {
	host, _ := ps.Host()
	info := host.Info()
	os := info.OS

	var arch string
	switch info.Architecture {
	case "x86_64":
		arch = "64 bit"
	case "x86":
		arch = "32 bit"
	}

	plat = os.Platform
	osFullName = fmt.Sprintf("%s, %s (build %s)", os.Name, arch, os.Build)
	return
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

// WindowsService holds windows service info
type WindowsService struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	DisplayName string `json:"display_name"`
	BinPath     string `json:"binpath"`
	Description string `json:"description"`
	Username    string `json:"username"`
	PID         uint32 `json:"pid"`
}

// GetServices returns a list of windows services
func (a *WindowsAgent) GetServices() []WindowsService {
	ret := make([]WindowsService, 0)
	services, err := svc.ListServices()
	if err != nil {
		a.Logger.Debugln(err)
		return ret
	}

	for _, s := range services {
		srv, err := svc.NewService(s.Name)
		if err == nil {
			derr := srv.GetServiceDetail()
			conf, qerr := srv.QueryServiceConfig()
			if derr == nil && qerr == nil {
				winsvc := WindowsService{
					Name:        s.Name,
					Status:      serviceStatusText(uint32(srv.Status.State)),
					DisplayName: conf.DisplayName,
					BinPath:     conf.BinaryPathName,
					Description: conf.Description,
					Username:    conf.ServiceStartName,
					PID:         uint32(srv.Status.Pid),
				}
				ret = append(ret, winsvc)
			} else {
				if derr != nil {
					a.Logger.Debugln(derr)
				}
				if qerr != nil {
					a.Logger.Debugln(qerr)
				}
			}
		}
	}
	return ret
}

//RecoverSalt recovers salt minion
func (a *WindowsAgent) RecoverSalt() {
	a.Logger.Debugln("Attempting salt recovery on", a.Hostname)
	// TODO
}

//RecoverMesh recovers mesh agent
func (a *WindowsAgent) RecoverMesh() {
	a.Logger.Debugln("Attempting mesh recovery on", a.Hostname)
	// TODO
}

//RecoverCMD runs shell recovery command
func (a *WindowsAgent) RecoverCMD(cmd string) {
	a.Logger.Debugln("Attempting shell recovery on", a.Hostname)
	// TODO
}
