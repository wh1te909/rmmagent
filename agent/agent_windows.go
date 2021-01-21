// Package agent todo change this
package agent

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	ps "github.com/elastic/go-sysinfo"
	"github.com/go-resty/resty/v2"
	"github.com/gonutz/w32"
	_ "github.com/mattn/go-sqlite3" // ok
	nats "github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
	wapf "github.com/wh1te909/go-win64api"
	rmm "github.com/wh1te909/rmmagent/shared"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	getDriveType = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDriveTypeW")
)

// WindowsAgent struct
type WindowsAgent struct {
	Hostname      string
	Arch          string
	AgentID       string
	BaseURL       string
	ApiURL        string
	Token         string
	AgentPK       int
	Cert          string
	ProgramDir    string
	EXE           string
	SystemDrive   string
	SaltCall      string
	Nssm          string
	SaltMinion    string
	SaltInstaller string
	MeshInstaller string
	MeshSystemEXE string
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
	pybin := filepath.Join(pd, "py3", "python.exe")
	sc := filepath.Join(sd, "\\salt\\salt-call.bat")
	nssm, mesh := ArchInfo(pd)

	if FileExists(dbFile) {
		migrateDBToReg(dbFile, logger)
	}

	var (
		baseurl string
		agentid string
		apiurl  string
		token   string
		agentpk string
		pk      int
		cert    string
	)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\TacticalRMM`, registry.ALL_ACCESS)
	if err == nil {
		baseurl, _, err = k.GetStringValue("BaseURL")
		if err != nil {
			logger.Fatalln("Unable to get BaseURL:", err)
		}

		agentid, _, err = k.GetStringValue("AgentID")
		if err != nil {
			logger.Fatalln("Unable to get AgentID:", err)
		}

		apiurl, _, err = k.GetStringValue("ApiURL")
		if err != nil {
			logger.Fatalln("Unable to get ApiURL:", err)
		}

		token, _, err = k.GetStringValue("Token")
		if err != nil {
			logger.Fatalln("Unable to get Token:", err)
		}

		agentpk, _, err = k.GetStringValue("AgentPK")
		if err != nil {
			logger.Fatalln("Unable to get AgentPK:", err)
		}

		pk, _ = strconv.Atoi(agentpk)

		cert, _, _ = k.GetStringValue("Cert")
	}

	headers := make(map[string]string)
	if len(token) > 0 {
		headers["Content-Type"] = "application/json"
		headers["Authorization"] = fmt.Sprintf("Token %s", token)
	}

	return &WindowsAgent{
		Hostname:      info.Hostname,
		Arch:          info.Architecture,
		BaseURL:       baseurl,
		AgentID:       agentid,
		ApiURL:        apiurl,
		Token:         token,
		AgentPK:       pk,
		Cert:          cert,
		ProgramDir:    pd,
		EXE:           exe,
		SystemDrive:   sd,
		SaltCall:      sc,
		Nssm:          nssm,
		MeshInstaller: mesh,
		MeshSystemEXE: filepath.Join(os.Getenv("ProgramFiles"), "Mesh Agent", "MeshAgent.exe"),
		MeshSVC:       "mesh agent",
		PyBin:         pybin,
		Headers:       headers,
		Logger:        logger,
		Version:       version,
		Debug:         logger.IsLevelEnabled(logrus.DebugLevel),
	}
}

func migrateDBToReg(dbFile string, logger *logrus.Logger) {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\TacticalRMM`, registry.ALL_ACCESS)
	if err == nil {
		return
	}

	db, err := sql.Open("sqlite3", dbFile)
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

	createRegKeys(server, agentid, saltmaster, token, strconv.Itoa(int(pk)), ret)
}

// ArchInfo returns arch specific filenames and urls
func ArchInfo(programDir string) (nssm, mesh string) {
	switch runtime.GOARCH {
	case "amd64":
		nssm = filepath.Join(programDir, "nssm.exe")
		mesh = "meshagent.exe"
	case "386":
		nssm = filepath.Join(programDir, "nssm-x86.exe")
		mesh = "meshagent-x86.exe"
	}
	return
}

// OSInfo returns os names formatted
func (a *WindowsAgent) OSInfo() (plat, osFullName string) {
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

// GetDisks returns a list of fixed disks
func (a *WindowsAgent) GetDisks() []rmm.Disk {
	ret := make([]rmm.Disk, 0)
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

		d := rmm.Disk{
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
			cmd = exec.Command("cmd.exe")
			cmd.SysProcAttr = &windows.SysProcAttr{
				CmdLine: fmt.Sprintf("cmd.exe /C %s", command),
			}
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
func (a *WindowsAgent) LoggedOnUser() string {
	users, err := wapf.ListLoggedInUsers()
	if err != nil {
		a.Logger.Debugln("LoggedOnUser error", err)
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

// RecoverTacticalAgent should only be called from the rpc service
func (a *WindowsAgent) RecoverTacticalAgent() {
	svc := "tacticalagent"
	a.Logger.Debugln("Attempting tacticalagent recovery on", a.Hostname)
	defer CMD(a.Nssm, []string{"start", svc}, 60, false)

	_, _ = CMD(a.Nssm, []string{"stop", svc}, 120, false)
	_, _ = CMD("ipconfig", []string{"/flushdns"}, 15, false)
	a.Logger.Debugln("Tacticalagent recovery completed on", a.Hostname)
}

// RecoverCheckRunner should only be called from the rpc service
func (a *WindowsAgent) RecoverCheckRunner() {
	svc := "checkrunner"
	a.Logger.Debugln("Attempting checkrunner recovery on", a.Hostname)
	defer CMD(a.Nssm, []string{"start", svc}, 60, false)

	_, _ = CMD(a.Nssm, []string{"stop", svc}, 120, false)
	_, _ = CMD("ipconfig", []string{"/flushdns"}, 15, false)
	a.Logger.Debugln("Checkrunner recovery completed on", a.Hostname)
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
	_, _ = CMD("ipconfig", []string{"/flushdns"}, 15, false)
	a.Logger.Debugln("Salt recovery completed on", a.Hostname)
}

func (a *WindowsAgent) SyncMeshNodeID(nc *nats.Conn) {
	var resp []byte
	ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))

	out, err := CMD(a.MeshSystemEXE, []string{"-nodeid"}, 10, false)
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
		a.Logger.Debugln("Failed getting mesh node id", stdout)
		return
	}

	payload := rmm.MeshNodeID{
		Func:    "syncmesh",
		Agentid: a.AgentID,
		NodeID:  StripAll(stdout),
	}
	ret.Encode(payload)
	nc.PublishRequest(a.AgentID, "syncmesh", resp)
}

//RecoverMesh recovers mesh agent
func (a *WindowsAgent) RecoverMesh(nc *nats.Conn) {
	a.Logger.Debugln("Attempting mesh recovery on", a.Hostname)
	defer CMD("net", []string{"start", a.MeshSVC}, 60, false)

	_, _ = CMD("net", []string{"stop", a.MeshSVC}, 60, false)
	a.ForceKillMesh()
	a.SyncMeshNodeID(nc)
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

func (a *WindowsAgent) Sync() {
	a.GetWMI()
	time.Sleep(1 * time.Second)
	a.SendSoftware()
}

func (a *WindowsAgent) SendSoftware() {
	sw := a.GetInstalledSoftware()
	a.Logger.Debugln(sw)

	url := a.BaseURL + "/api/v3/software/"
	payload := map[string]interface{}{"agent_id": a.AgentID, "software": sw}

	req := APIRequest{
		URL:       url,
		Method:    "POST",
		Payload:   payload,
		Headers:   a.Headers,
		Timeout:   15,
		LocalCert: a.Cert,
		Debug:     a.Debug,
	}

	_, err := req.MakeRequest()
	if err != nil {
		a.Logger.Debugln(err)
	}
}

func (a *WindowsAgent) UninstallCleanup() {
	registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\TacticalRMM`)
	a.CleanupAgentUpdates()
	CleanupSchedTasks()
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

func (a *WindowsAgent) installerMsg(msg, alert string, silent bool) {
	window := w32.GetForegroundWindow()
	if !silent && window != 0 {
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
	time.Sleep(time.Duration(randRange(1, 15)) * time.Second)
	a.CleanupAgentUpdates()
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
		CMD("net", []string{"start", "tacticalrpc"}, 10, false)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("Download failed with status code", r.StatusCode())
		CMD("net", []string{"start", "tacticalrpc"}, 10, false)
		return
	}

	dir, err := ioutil.TempDir("", "tacticalrmm")
	if err != nil {
		a.Logger.Errorln("Agentupdate create tempdir:", err)
		CMD("net", []string{"start", "tacticalrpc"}, 10, false)
		return
	}

	innoLogFile := filepath.Join(dir, "tacticalrmm.txt")

	args := []string{"/C", updater, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/FORCECLOSEAPPLICATIONS", "/NORESTARTAPPLICATIONS", fmt.Sprintf("/LOG=%s", innoLogFile)}
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Start()
	time.Sleep(1 * time.Second)
}

func (a *WindowsAgent) setupNatsOptions() []nats.Option {
	opts := make([]nats.Option, 0)
	opts = append(opts, nats.Name("TacticalRMM"))
	opts = append(opts, nats.UserInfo(a.AgentID, a.Token))
	opts = append(opts, nats.ReconnectWait(time.Second*5))
	opts = append(opts, nats.RetryOnFailedConnect(true))
	opts = append(opts, nats.MaxReconnects(-1))
	opts = append(opts, nats.ReconnectBufSize(-1))
	return opts
}

func (a *WindowsAgent) GetUninstallExe() string {
	cderr := os.Chdir(a.ProgramDir)
	if cderr == nil {
		files, err := filepath.Glob("unins*.exe")
		if err == nil {
			for _, f := range files {
				if strings.Contains(f, "001") {
					return f
				}
			}
		}
	}
	return "unins000.exe"
}

func (a *WindowsAgent) AgentUninstall() {
	tacUninst := filepath.Join(a.ProgramDir, a.GetUninstallExe())
	args := []string{"/C", tacUninst, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/FORCECLOSEAPPLICATIONS"}
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Start()
}

func (a *WindowsAgent) CleanupAgentUpdates() {
	cderr := os.Chdir(a.ProgramDir)
	if cderr != nil {
		a.Logger.Errorln(cderr)
		return
	}

	files, err := filepath.Glob("winagent-v*.exe")
	if err == nil {
		for _, f := range files {
			os.Remove(f)
		}
	}

	cderr = os.Chdir(os.Getenv("TMP"))
	if cderr != nil {
		a.Logger.Errorln(cderr)
		return
	}
	folders, err := filepath.Glob("tacticalrmm*")
	if err == nil {
		for _, f := range folders {
			os.RemoveAll(f)
		}
	}
}

func (a *WindowsAgent) GetPython(force bool) {
	if FileExists(a.PyBin) && !force {
		return
	}

	pyZip := filepath.Join(a.ProgramDir, "py3.zip")
	defer os.Remove(pyZip)

	if force {
		os.RemoveAll(filepath.Join(a.ProgramDir, "py3"))
	}

	rClient := resty.New()
	rClient.SetTimeout(25 * time.Minute)

	r, err := rClient.R().SetOutput(pyZip).Get("https://files.xlawgaming.com/py3.zip")
	if err != nil {
		a.Logger.Errorln("Unable to download py3.zip:", err)
	}
	if r.IsError() {
		a.Logger.Errorln("Unable to download py3.zip. Status code", r.StatusCode())
	}

	err = Unzip(pyZip, a.ProgramDir)
	if err != nil {
		a.Logger.Errorln(err)
	}
	time.Sleep(1 * time.Second)
}
