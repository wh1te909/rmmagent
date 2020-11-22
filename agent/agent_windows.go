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
	"github.com/go-resty/resty/v2"
	"github.com/gonutz/w32"
	_ "github.com/mattn/go-sqlite3" // ok
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/sirupsen/logrus"
	wapf "github.com/wh1te909/go-win64api"
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
func CMDShell(shell string, cmdArgs []string, command string, timeout int, detached bool) (output [2]string, e error) {
	var (
		outb     bytes.Buffer
		errb     bytes.Buffer
		cmd      *exec.Cmd
		timedOut bool = false
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if len(cmdArgs) > 0 && command == "" {
		switch shell {
		case "cmd":
			cmdArgs = append([]string{"/C"}, cmdArgs...)
			cmd = exec.Command("cmd.exe", cmdArgs...)
		case "powershell":
			cmdArgs = append([]string{"-NonInteractive", "-NoProfile"}, cmdArgs...)
			cmd = exec.Command("powershell.exe", cmdArgs...)
		}
	} else {
		switch shell {
		case "cmd":
			cmd = exec.Command("cmd.exe", "/C", command)
		case "powershell":
			cmd = exec.Command("Powershell", "-NonInteractive", "-NoProfile", command)
		}
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
	_, err := CMDShell("cmd", args, cmd, 10, false)
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
	_, cerr := CMDShell("cmd", args, cmd, 10, false)
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
			_, _ = CMDShell("cmd", args, fmt.Sprintf("powercfg /set%svalueindex scheme_current sub_buttons lidaction 0", c), 5, false)
			_, _ = CMDShell("cmd", args, fmt.Sprintf("powercfg /x -standby-timeout-%s 0", c), 5, false)
			_, _ = CMDShell("cmd", args, fmt.Sprintf("powercfg /x -hibernate-timeout-%s 0", c), 5, false)
			_, _ = CMDShell("cmd", args, fmt.Sprintf("powercfg /x -disk-timeout-%s 0", c), 5, false)
			_, _ = CMDShell("cmd", args, fmt.Sprintf("powercfg /x -monitor-timeout-%s 0", c), 5, false)
		}(i)
	}
	wg.Wait()
	_, _ = CMDShell("cmd", args, "powercfg -S SCHEME_CURRENT", 5, false)
}

// LoggedOnUser returns the first logged on user it finds
func LoggedOnUser() string {
	users, err := wapf.ListLoggedInUsers()
	if err != nil {
		return "None"
	}

	if len(users) == 0 {
		return "None"
	}

	for _, u := range users {
		// remove the computername or domain
		return strings.Split(u.FullUser(), `\`)[1]
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
	defer CMD(a.Nssm, []string{"start", saltSVC}, 60, false)

	_, _ = CMD(a.Nssm, []string{"stop", saltSVC}, 120, false)
	a.ForceKillSalt()
	time.Sleep(2 * time.Second)
	cacheDir := filepath.Join(a.SystemDrive, "\\salt", "var", "cache", "salt", "minion")
	a.Logger.Debugln("Clearing salt cache in", cacheDir)
	err := os.RemoveAll(cacheDir)
	if err != nil {
		a.Logger.Debugln(err)
	}
	_, _ = CMD("ipconfig", []string{"flushdns"}, 15, false)
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

	url := fmt.Sprintf("%s/api/v3/%d/meshinfo/", a.Server, a.AgentPK)
	req := APIRequest{
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
	defer CMD("net", []string{"start", a.MeshSVC}, 60, false)

	_, _ = CMD("net", []string{"stop", a.MeshSVC}, 60, false)
	a.ForceKillMesh()
	a.SyncMeshNodeID()
}

//RecoverRPC recovers nats rpc service
func (a *WindowsAgent) RecoverRPC() {
	a.Logger.Debugln("Attempting rpc recovery on", a.Hostname)
	_, _ = CMD("net", []string{"stop", "tacticalrpc"}, 90, false)
	time.Sleep(2 * time.Second)
	_, _ = CMD("net", []string{"start", "tacticalrpc"}, 90, false)
}

//RecoverCMD runs a shell recovery command
func (a *WindowsAgent) RecoverCMD(command string) {
	a.Logger.Infoln("Attempting shell recovery with command:", command)
	// call the command with cmd /C so that the parent process is cmd
	// and not tacticalrmm.exe so that we don't kill ourself
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		CmdLine:       fmt.Sprintf("cmd.exe /C %s", command), // properly escape in case double quotes are in the command
	}
	cmd.Start()
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
func ShowStatus(version string) {
	statusMap := make(map[string]string)
	svcs := []string{"tacticalagent", "checkrunner", "tacticalrpc", "salt-minion", "mesh agent"}

	for _, service := range svcs {
		status, err := GetServiceStatus(service)
		if err != nil {
			statusMap[service] = "Not Installed"
			continue
		}
		statusMap[service] = status
	}

	window := w32.GetForegroundWindow()
	if window != 0 {
		_, consoleProcID := w32.GetWindowThreadProcessId(window)
		if w32.GetCurrentProcessId() == consoleProcID {
			w32.ShowWindow(window, w32.SW_HIDE)
		}
		var handle w32.HWND
		msg := fmt.Sprintf("Agent: %s\n\nCheck Runner: %s\n\nRPC Service: %s\n\nSalt Minion: %s\n\nMesh Agent: %s",
			statusMap["tacticalagent"], statusMap["checkrunner"], statusMap["tacticalrpc"],
			statusMap["salt-minion"], statusMap["mesh agent"],
		)
		w32.MessageBox(handle, msg, fmt.Sprintf("Tactical RMM v%s", version), w32.MB_OK|w32.MB_ICONINFORMATION)
	} else {
		fmt.Println("Tactical RMM Version", version)
		fmt.Println("Agent:", statusMap["tacticalagent"])
		fmt.Println("Check Runner:", statusMap["checkrunner"])
		fmt.Println("RPC Service:", statusMap["tacticalrpc"])
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

func (a *WindowsAgent) AgentUpdate(url, inno, version string) {
	updater := filepath.Join(a.ProgramDir, inno)
	a.Logger.Infof("Agent updating from %s to %s", a.Version, version)
	a.Logger.Infoln("Downloading agent update from", url)

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(15 * time.Minute)
	rClient.SetDebug(a.Debug)
	r, err := rClient.R().SetOutput(updater).Get(url)
	if err != nil {
		a.Logger.Errorln(err)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("Download failed with status code", r.StatusCode())
		return
	}

	args := []string{"/C", updater, "/VERYSILENT", "/SUPPRESSMSGBOXES"}
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Start()
}

// CleanupPythonAgent cleans up files from the old python agent if this is an upgrade
func (a *WindowsAgent) CleanupPythonAgent() {
	cderr := os.Chdir(a.ProgramDir)
	if cderr != nil {
		return
	}

	fileMatches := []string{
		"*.dll",
		"*.pyd",
		"base_library*",
		"*.manifest",
		"onit.ico",
		"VERSION",
	}

	for _, match := range fileMatches {
		files, err := filepath.Glob(match)
		if err == nil {
			for _, f := range files {
				os.Remove(f)
			}
		}
	}

	folderMatches := []string{
		"certifi",
		"Include",
		"lib2to3",
		"psutil",
		"tcl",
		"tk",
	}

	for _, match := range folderMatches {
		folders, err := filepath.Glob(match)
		if err == nil {
			for _, f := range folders {
				os.RemoveAll(f)
			}
		}
	}

	_, _ = a.LocalSaltCall("task.delete_task", []string{"TacticalRMM_fixsalt"}, 45)
}

// UpdateSalt downloads the latest salt minion and performs an update
func (a *WindowsAgent) UpdateSalt() {
	url := fmt.Sprintf("%s/api/v3/%s/saltminion/", a.Server, a.AgentID)
	req := APIRequest{
		URL:       url,
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.DB.Cert,
		Debug:     a.Debug,
	}

	req.Method = "GET"
	a.Logger.Debugln(req)

	r, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
		return
	}

	if r.IsError() {
		return
	}

	type SaltResp struct {
		CurrentVer  string `json:"currentVer"`
		LatestVer   string `json:"latestVer"`
		SaltID      string `json:"salt_id"`
		DownloadURL string `json:"downloadURL"`
	}
	data := SaltResp{}

	if err := json.Unmarshal(r.Body(), &data); err != nil {
		a.Logger.Debugln(err)
		return
	}

	installedVer := a.GetProgramVersion("salt minion")
	if data.LatestVer == installedVer {
		a.Logger.Warnf("Salt latest ver %s same as installed ver %s. Skipping.\n", data.LatestVer, installedVer)
		return
	}

	a.Logger.Infof("Updating salt from %s to %s\n", installedVer, data.LatestVer)

	minion := filepath.Join(a.ProgramDir, a.SaltInstaller)
	if FileExists(minion) {
		_ = os.Remove(minion)
	}

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(45 * time.Minute)

	r1, derr := rClient.R().SetOutput(minion).Get(data.DownloadURL)
	if derr != nil {
		a.Logger.Errorln("Unable to download salt-minion for update:", derr)
		return
	}

	if r1.IsError() {
		a.Logger.Errorln("Unable to download salt-minion for update:", r1.StatusCode())
		return
	}
	_, _ = CMD(a.Nssm, []string{"stop", "salt-minion"}, 120, false)
	_ = os.Chdir(a.ProgramDir)

	updateArgs := []string{
		"/S",
		"/custom-config=saltcustom",
		fmt.Sprintf("/master=%s", a.DB.SaltMaster),
		fmt.Sprintf("/minion-name=%s", data.SaltID),
		"/start-minion=1",
	}

	_, saltErr := CMD(a.SaltInstaller, updateArgs, 900, false)

	if saltErr != nil {
		a.Logger.Errorln("Failed to update salt:", saltErr)
		_, _ = CMD(a.Nssm, []string{"start", "salt-minion"}, 60, false)
		return
	}

	req.URL = a.Server + "/api/v3/saltminion/"
	req.Method = "PUT"
	req.Payload = map[string]string{"ver": data.LatestVer, "agent_id": a.AgentID}
	_, _ = req.MakeRequest()

	a.Logger.Infof("Salt was updated from %s to %s\n", installedVer, data.LatestVer)
}
