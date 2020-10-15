// Package agent todo change this
package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/gonutz/w32"
	_ "github.com/mattn/go-sqlite3" // ok
	"github.com/shirou/gopsutil/disk"
	svc "github.com/shirou/gopsutil/winservices"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	getDriveType = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDriveTypeW")
)

// WindowsAgent struct
type WindowsAgent struct {
	DB
	Host
	ProgramDir    string
	EXE           string
	SystemDrive   string
	SaltCall      string
	Nssm          string
	SaltMinion    string
	SaltInstaller string
	MeshInstaller string
	MeshSVC       string
	PyBin         string
	Headers       map[string]string
	Logger        *logrus.Logger
	Version       string
	Debug         bool
}

// New __init__
func New(logger *logrus.Logger, version string) *WindowsAgent {
	host, _ := ps.Host()
	info := host.Info()
	pd := filepath.Join(os.Getenv("ProgramFiles"), "TacticalAgent")
	exe := filepath.Join(pd, "tacticalrmm.exe")
	dbFile := filepath.Join(pd, "agentdb.db")
	sd := os.Getenv("SystemDrive")
	pybin := filepath.Join(sd, "\\salt", "bin", "python.exe")
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
		EXE:           exe,
		SystemDrive:   sd,
		SaltCall:      sc,
		Nssm:          nssm,
		SaltMinion:    saltexe,
		SaltInstaller: saltinstaller,
		MeshInstaller: mesh,
		MeshSVC:       "mesh agent",
		PyBin:         pybin,
		Headers:       headers,
		Logger:        logger,
		Version:       version,
		Debug:         logger.IsLevelEnabled(logrus.DebugLevel),
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
		if err != nil {
			continue
		}

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

// CMDShell mimics python's `subprocess.run(shell=True)`
func CMDShell(cmdArgs []string, command string, timeout int, detached bool) (output [2]string, e error) {
	var (
		outb     bytes.Buffer
		errb     bytes.Buffer
		cmd      *exec.Cmd
		timedOut bool = false
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if len(cmdArgs) > 0 && command == "" {
		cmdArgs = append([]string{"/C"}, cmdArgs...)
		cmd = exec.Command("cmd.exe", cmdArgs...)
	} else {
		cmd = exec.Command("cmd.exe", "/C", command)
	}

	// https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
	if detached {
		cmd.SysProcAttr = &windows.SysProcAttr{
			CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		}
	}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()

	pid := int32(cmd.Process.Pid)

	go func(p int32) {

		<-ctx.Done()

		_ = KillProc(p)
		timedOut = true
	}(pid)

	err = cmd.Wait()

	if timedOut {
		return [2]string{outb.String(), errb.String()}, ctx.Err()
	}

	if err != nil {
		return [2]string{outb.String(), errb.String()}, err
	}

	return [2]string{outb.String(), errb.String()}, nil
}

// CMD runs a command with shell=False
func CMD(exe string, args []string, timeout int, detached bool) (output [2]string, e error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var outb, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, exe, args...)
	if detached {
		cmd.SysProcAttr = &windows.SysProcAttr{
			CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		}
	}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return [2]string{"", ""}, fmt.Errorf("%s: %s", err, errb.String())
	}

	if ctx.Err() == context.DeadlineExceeded {
		return [2]string{"", ""}, ctx.Err()
	}

	return [2]string{outb.String(), errb.String()}, nil
}

// EnablePing enables ping
func EnablePing() {
	args := make([]string, 0)
	cmd := `netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow`
	_, err := CMDShell(args, cmd, 10, false)
	if err != nil {
		fmt.Println(err)
	}
}

// EnableRDP enables Remote Desktop
func EnableRDP() {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.ALL_ACCESS)
	if err != nil {
		fmt.Println(err)
	}
	defer k.Close()

	err = k.SetDWordValue("fDenyTSConnections", 0)
	if err != nil {
		fmt.Println(err)
	}

	args := make([]string, 0)
	cmd := `netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
	_, cerr := CMDShell(args, cmd, 10, false)
	if cerr != nil {
		fmt.Println(cerr)
	}
}

// DisableSleepHibernate disables sleep and hibernate
func DisableSleepHibernate() {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.ALL_ACCESS)
	if err != nil {
		fmt.Println(err)
	}
	defer k.Close()

	err = k.SetDWordValue("HiberbootEnabled", 0)
	if err != nil {
		fmt.Println(err)
	}

	args := make([]string, 0)

	var wg sync.WaitGroup
	currents := []string{"ac", "dc"}
	for _, i := range currents {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			_, _ = CMDShell(args, fmt.Sprintf("powercfg /set%svalueindex scheme_current sub_buttons lidaction 0", c), 5, false)
			_, _ = CMDShell(args, fmt.Sprintf("powercfg /x -standby-timeout-%s 0", c), 5, false)
			_, _ = CMDShell(args, fmt.Sprintf("powercfg /x -hibernate-timeout-%s 0", c), 5, false)
			_, _ = CMDShell(args, fmt.Sprintf("powercfg /x -disk-timeout-%s 0", c), 5, false)
			_, _ = CMDShell(args, fmt.Sprintf("powercfg /x -monitor-timeout-%s 0", c), 5, false)
		}(i)
	}
	wg.Wait()
	_, _ = CMDShell(args, "powercfg -S SCHEME_CURRENT", 5, false)
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

// ForceKillSalt kills all salt related processes
func (a *WindowsAgent) ForceKillSalt() {
	pids := make([]int, 0)

	procs, err := ps.Processes()
	if err != nil {
		return
	}

	for _, process := range procs {
		p, err := process.Info()
		if err != nil {
			continue
		}
		if strings.ToLower(p.Name) == "python.exe" && strings.Contains(strings.ToLower(p.Exe), "salt") {
			pids = append(pids, p.PID)
		}
	}

	for _, pid := range pids {
		a.Logger.Debugln("Killing salt process with pid %d", pid)
		if err := KillProc(int32(pid)); err != nil {
			a.Logger.Debugln(err)
		}
	}
}

// ForceKillMesh kills all mesh agent related processes
func (a *WindowsAgent) ForceKillMesh() {
	pids := make([]int, 0)

	procs, err := ps.Processes()
	if err != nil {
		return
	}

	for _, process := range procs {
		p, err := process.Info()
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(p.Name), "meshagent") {
			pids = append(pids, p.PID)
		}
	}

	for _, pid := range pids {
		a.Logger.Debugln("Killing mesh process with pid %d", pid)
		if err := KillProc(int32(pid)); err != nil {
			a.Logger.Debugln(err)
		}
	}
}

//RecoverSalt recovers the salt minion
func (a *WindowsAgent) RecoverSalt() {
	saltSVC := "salt-minion"
	a.Logger.Debugln("Attempting salt recovery on", a.Hostname)
	defer CMD(a.Nssm, []string{"start", saltSVC}, 45, false)

	CMD(a.Nssm, []string{"stop", saltSVC}, 45, false)
	WaitForService(saltSVC, "stopped", 15)
	a.ForceKillSalt()
	CMD("ipconfig", []string{"flushdns"}, 15, false)
	a.Logger.Debugln("Salt recovery completed on", a.Hostname)
}

func (a *WindowsAgent) getMeshEXE() (meshexe string) {
	mesh1 := filepath.Join(os.Getenv("ProgramFiles"), "Mesh Agent", "MeshAgent.exe")
	mesh2 := filepath.Join(a.ProgramDir, a.MeshInstaller)
	if FileExists(mesh1) {
		meshexe = mesh1
	} else {
		meshexe = mesh2
	}
	return meshexe
}

func (a *WindowsAgent) SyncMeshNodeID() {
	meshexe := a.getMeshEXE()

	out, err := CMD(meshexe, []string{"-nodeidhex"}, 10, false)
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	stdout := out[0]
	stderr := out[1]

	if stderr != "" {
		a.Logger.Debugln(stderr)
		return
	}

	if stdout == "" || strings.Contains(strings.ToLower(StripAll(stdout)), "not defined") {
		a.Logger.Debugln("Failed to get node id hex", stdout)
		return
	}

	url := fmt.Sprintf("%s/api/v1/%d/meshinfo/", a.Server, a.AgentPK)
	req := &APIRequest{
		URL:       url,
		Method:    "GET",
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	resp, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	a.Logger.Debugln("Local Mesh:", StripAll(stdout))
	a.Logger.Debugln("RMM Mesh:", DjangoStringResp(resp.String()))
	a.Logger.Debugln("Status code:", resp.StatusCode())

	if resp.StatusCode() == 200 && StripAll(stdout) != DjangoStringResp(resp.String()) {
		payload := struct {
			NodeIDHex string `json:"nodeidhex"`
		}{NodeIDHex: StripAll(stdout)}

		req.Method = "PATCH"
		req.Payload = payload
		if _, err := req.MakeRequest(); err != nil {
			a.Logger.Debugln(err)
		}
	}
}

//RecoverMesh recovers mesh agent
func (a *WindowsAgent) RecoverMesh() {
	a.Logger.Debugln("Attempting mesh recovery on", a.Hostname)
	defer CMD("sc.exe", []string{"start", a.MeshSVC}, 20, false)

	args := []string{"stop", a.MeshSVC}
	CMD("sc.exe", args, 45, false)
	WaitForService(a.MeshSVC, "stopped", 5)
	a.ForceKillMesh()
	a.SyncMeshNodeID()
}

//RecoverCMD runs a shell recovery command
func (a *WindowsAgent) RecoverCMD(command string) {
	a.Logger.Debugln("Attempting shell recovery on", a.Hostname)
	a.Logger.Debugln(command)
	_, _ = CMDShell([]string{}, command, 18000, true)
}

func (a *WindowsAgent) LocalSaltCall(saltfunc string, args []string, timeout int) ([]byte, error) {
	var outb, errb bytes.Buffer
	var bytesErr []byte
	largs := len(args)
	saltArgs := make([]string, 0)

	saltArgs = []string{saltfunc}

	if largs > 0 {
		saltArgs = append(saltArgs, args...)
	}

	saltArgs = append(saltArgs, "--local", fmt.Sprintf("--timeout=%d", timeout))

	cmd := exec.Command(a.SaltCall, saltArgs...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		a.Logger.Debugln(err)
		return bytesErr, err
	}
	return outb.Bytes(), nil
}

func (a *WindowsAgent) CreateMeshWatchDogTask() {
	t := time.Now().Local().Add(5 * time.Minute)
	f := fmt.Sprintf("%02d:%02d", t.Hour(), t.Minute())

	args := []string{
		"name=TacticalRMM_fixmesh",
		"force=True",
		"action_type=Execute",
		fmt.Sprintf(`cmd="%s"`, a.EXE),
		`arguments='-m fixmesh'`,
		"trigger_type=Daily",
		fmt.Sprintf(`start_time='%s'`, f),
		`repeat_interval='1 hour'`,
		"ac_only=False",
		"stop_if_on_batteries=False",
	}

	_, err := a.LocalSaltCall("task.create_task", args, 60)
	if err != nil {
		a.Logger.Debugln(err)
	}
}

func (a *WindowsAgent) UninstallCleanup() {
	out, err := a.LocalSaltCall("task.list_tasks", []string{}, 45)
	if err != nil {
		return
	}

	type LocalSaltTasks struct {
		Local []string `json:"local"`
	}

	data := LocalSaltTasks{}
	if err := json.Unmarshal(out, &data); err != nil {
		return
	}

	for _, task := range data.Local {
		if strings.HasPrefix(task, "TacticalRMM_") {
			_, err := a.LocalSaltCall("task.delete_task", []string{task}, 45)
			if err != nil {
				continue
			}
		}
	}
}

// ShowStatus prints windows service status
// If called from an interactive desktop, pops up a message box
// Otherwise prints to the console
func ShowStatus() {
	statusMap := make(map[string]string)
	svcs := []string{"tacticalagent", "checkrunner", "salt-minion", "mesh agent"}

	for _, service := range svcs {
		srv, err := WinServiceGet(service)
		if err != nil {
			statusMap[service] = "Not Installed"
			continue
		}
		if derr := srv.GetServiceDetail(); derr != nil {
			statusMap[service] = "Unknown"
			continue
		}
		statusMap[service] = serviceStatusText(uint32(srv.Status.State))
	}

	window := w32.GetForegroundWindow()
	if window != 0 {
		_, consoleProcID := w32.GetWindowThreadProcessId(window)
		if w32.GetCurrentProcessId() == consoleProcID {
			w32.ShowWindow(window, w32.SW_HIDE)
		}
		var handle w32.HWND
		msg := fmt.Sprintf("Agent: %s\n\nCheck Runner: %s\n\nSalt Minion: %s\n\nMesh Agent: %s",
			statusMap["tacticalagent"], statusMap["checkrunner"],
			statusMap["salt-minion"], statusMap["mesh agent"],
		)
		w32.MessageBox(handle, msg, "Tactical RMM", w32.MB_OK|w32.MB_ICONINFORMATION)
	} else {
		fmt.Println("Agent:", statusMap["tacticalagent"])
		fmt.Println("Check Runner:", statusMap["checkrunner"])
		fmt.Println("Salt Minion:", statusMap["salt-minion"])
		fmt.Println("Mesh Agent:", statusMap["mesh agent"])
	}
}

func (a *WindowsAgent) installerMsg(msg, alert string) {
	window := w32.GetForegroundWindow()
	if window != 0 {
		var (
			handle w32.HWND
			flags  uint
		)

		switch alert {
		case "info":
			flags = w32.MB_OK | w32.MB_ICONINFORMATION
		case "error":
			flags = w32.MB_OK | w32.MB_ICONERROR
		default:
			flags = w32.MB_OK | w32.MB_ICONINFORMATION
		}

		w32.MessageBox(handle, msg, "Tactical RMM", flags)
	} else {
		fmt.Println(msg)
	}

	if alert == "error" {
		a.Logger.Fatalln(msg)
	}
}
