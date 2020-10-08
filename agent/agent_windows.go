// Package agent todo change this
package agent

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	ps "github.com/elastic/go-sysinfo"
	_ "github.com/mattn/go-sqlite3" // ok
	"github.com/shirou/gopsutil/disk"
	svc "github.com/shirou/gopsutil/winservices"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var wg sync.WaitGroup

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

// WindowsService holds windows service info
type WindowsService struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	DisplayName string `json:"display_name"`
	BinPath     string `json:"binpath"`
	Description string `json:"description"`
	Username    string `json:"username"`
	PID         uint32 `json:"pid"`
	StartType   string `json:"start_type"`
}

// WinServiceGet mimics psutils win_service_get
func WinServiceGet(name string) (*svc.Service, error) {
	srv, err := svc.NewService(name)
	if err != nil {
		return &svc.Service{}, err
	}
	return srv, nil
}

// WaitForService will wait for a service to be in X state for X retries
func WaitForService(name string, status string, retries int) {
	attempts := 0
	for {
		service, err := WinServiceGet(name)
		if err != nil {
			attempts++
			time.Sleep(5 * time.Second)
		} else {
			service.GetServiceDetail()
			stat := serviceStatusText(uint32(service.Status.State))
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
					StartType:   serviceStartType(uint32(conf.StartType)),
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

// Disk holds physical disk info
type Disk struct {
	Device  string  `json:"device"`
	Fstype  string  `json:"fstype"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Free    uint64  `json:"free"`
	Percent float64 `json:"percent"`
}

// GetDisks returns a list of fixed disks
func (a *WindowsAgent) GetDisks() []Disk {
	ret := make([]Disk, 0)
	partitions, err := disk.Partitions(false)
	if err != nil {
		a.Logger.Debugln(err)
		return ret
	}

	var getDriveType = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDriveTypeW")

	for _, p := range partitions {
		typepath, _ := windows.UTF16PtrFromString(p.Device)
		typeval, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(typepath)))
		// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea
		if typeval != 3 {
			continue
		}

		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}

		d := Disk{
			Device:  p.Device,
			Fstype:  p.Fstype,
			Total:   usage.Total,
			Used:    usage.Used,
			Free:    usage.Free,
			Percent: usage.UsedPercent,
		}
		ret = append(ret, d)
	}
	return ret
}

// CMDShellNoOutput runs a command with shell=True, does not return output
func CMDShellNoOutput(arg string, timeout int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd.exe", "/C", arg)
	cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return
	}
}

// CMDNoOutput runs a command with shell=False, does not return output
func CMDNoOutput(exe string, args []string, timeout int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return
	}
}

// EnablePing enables ping
func EnablePing() {
	fmt.Println("Enabling ping...")
	cmd := `netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow`
	CMDShellNoOutput(cmd, 5)
}

// EnableRDP enables Remote Desktop
func EnableRDP() {
	fmt.Println("Enabling RDP...")
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.ALL_ACCESS)
	if err != nil {
		fmt.Println(err)
	}
	defer k.Close()

	err = k.SetDWordValue("fDenyTSConnections", 0)
	if err != nil {
		fmt.Println(err)
	}

	cmd := `netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
	CMDShellNoOutput(cmd, 5)
}

// DisableSleepHibernate disables sleep and hibernate
func DisableSleepHibernate() {
	fmt.Println("Disabling sleep/hibernate...")
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.ALL_ACCESS)
	if err != nil {
		fmt.Println(err)
	}
	defer k.Close()

	err = k.SetDWordValue("HiberbootEnabled", 0)
	if err != nil {
		fmt.Println(err)
	}

	currents := []string{"ac", "dc"}
	timeout := 5
	for _, i := range currents {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			CMDShellNoOutput(fmt.Sprintf("powercfg /set%svalueindex scheme_current sub_buttons lidaction 0", c), timeout)
			CMDShellNoOutput(fmt.Sprintf("powercfg /x -standby-timeout-%s 0", c), timeout)
			CMDShellNoOutput(fmt.Sprintf("powercfg /x -hibernate-timeout-%s 0", c), timeout)
			CMDShellNoOutput(fmt.Sprintf("powercfg /x -disk-timeout-%s 0", c), timeout)
			CMDShellNoOutput(fmt.Sprintf("powercfg /x -monitor-timeout-%s 0", c), timeout)
		}(i)
	}
	wg.Wait()
	CMDShellNoOutput("powercfg -S SCHEME_CURRENT", timeout)
}

// LoggedOnUser returns active logged on console user
func LoggedOnUser() string {
	qwinsta := filepath.Join(os.Getenv("WINDIR"), "System32", "qwinsta.exe")
	out, err := exec.Command(qwinsta).Output()
	if err != nil {
		return "None"
	}
	lines := strings.Split(string(out), "\n")
	for _, i := range lines {
		if strings.Contains(i, "console") && strings.Contains(i, "Active") {
			words := strings.Fields(i)
			if len(words) > 3 {
				return words[1]
			}
		} else if strings.Contains(i, "rdp") && strings.Contains(i, "Active") {
			words := strings.Fields(i)
			if len(words) > 3 {
				return words[1]
			}
		}
	}
	return "None"
}

//RecoverSalt recovers the salt minion
func (a *WindowsAgent) RecoverSalt() {
	saltSVC := "salt-minion"
	a.Logger.Debugln("Attempting salt recovery on", a.Hostname)
	args := []string{"stop", saltSVC}
	CMDNoOutput(a.Nssm, args, 45)
	WaitForService(saltSVC, "stopped", 15)
	args = []string{"flushdns"}
	CMDNoOutput("ipconfig", args, 15)
	args = []string{"start", saltSVC}
	CMDNoOutput(a.Nssm, args, 45)
	a.Logger.Debugln("Salt recovery completed on", a.Hostname)
}

//RecoverMesh recovers mesh agent
func (a *WindowsAgent) RecoverMesh() {
	a.Logger.Debugln("Attempting mesh recovery on", a.Hostname)
	// TODO
}

//RecoverCMD runs a shell recovery command
func (a *WindowsAgent) RecoverCMD(command string) {
	a.Logger.Debugln("Attempting shell recovery on", a.Hostname)
	a.Logger.Debugln(command)
	cmd := exec.Command("cmd.exe", "/C", command)
	if err := cmd.Run(); err != nil {
		a.Logger.Debugln(err)
	}
}
