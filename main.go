package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/wh1te909/rmmagent/agent"
)

var (
	version = "1.1.9"
	log     = logrus.New()
	logFile *os.File
)

func main() {
	hostname, _ := os.Hostname()
	ver := flag.Bool("version", false, "Prints version")
	mode := flag.String("m", "", "The mode to run")
	taskPK := flag.Int("p", 0, "Task PK")
	logLevel := flag.String("log", "INFO", "The log level")
	logTo := flag.String("logto", "file", "Where to log to")
	api := flag.String("api", "", "API URL")
	clientID := flag.Int("client-id", 0, "Client ID")
	siteID := flag.Int("site-id", 0, "Site ID")
	timeout := flag.Duration("timeout", 900, "Installer timeout (seconds)")
	desc := flag.String("desc", hostname, "Agent's Description")
	atype := flag.String("agent-type", "server", "server or workstation")
	token := flag.String("auth", "", "Token")
	power := flag.Bool("power", false, "Disable sleep/hibernate")
	rdp := flag.Bool("rdp", false, "Enable RDP")
	ping := flag.Bool("ping", false, "Enable ping")
	nosalt := flag.Bool("nosalt", false, "Does not install salt")
	localMesh := flag.String("local-mesh", "", "Path to mesh executable")
	cert := flag.String("cert", "", "Path to domain CA .pem")
	updateurl := flag.String("updateurl", "", "Download link to updater")
	inno := flag.String("inno", "", "Inno setup file")
	updatever := flag.String("updatever", "", "Update version")
	silent := flag.Bool("silent", false, "Do not popup any message boxes during installation")
	flag.Parse()

	if *ver {
		agent.ShowVersionInfo(version)
		return
	}

	if len(os.Args) == 1 {
		agent.ShowStatus(version)
		return
	}

	setupLogging(logLevel, logTo)
	defer logFile.Close()

	a := *agent.New(log, version)

	switch *mode {
	case "rpc":
		a.RunRPC()
	case "pk":
		fmt.Println(a.AgentPK)
	case "checkrunner":
		a.CheckRunner()
	case "winagentsvc":
		a.WinAgentSvc()
	case "runchecks":
		a.RunChecks()
	case "sysinfo":
		a.GetWMI()
	case "software":
		a.SendSoftware()
	case "sync":
		a.Sync()
	case "checkin":
		a.CheckIn()
	case "basicinfo":
		a.SysInfo()
	case "startup":
		a.AgentStartup()
	case "recoversalt":
		a.RecoverSalt()
	case "recovermesh":
		a.RecoverMesh()
	case "winupdater":
		a.InstallPatches()
	case "fixmesh":
		a.SyncMeshNodeID()
	case "cleanup":
		a.UninstallCleanup()
	case "installsalt":
		a.InstallSalt()
	case "fixsalt": // deprecated, will be removed in future release
		return
	case "publicip":
		fmt.Println(a.PublicIP())
	case "taskrunner":
		if len(os.Args) < 5 || *taskPK == 0 {
			return
		}
		a.RunTask(*taskPK)
	case "update":
		if *updateurl == "" || *inno == "" || *updatever == "" {
			updateUsage()
			return
		}
		a.AgentUpdate(*updateurl, *inno, *updatever)
	case "install":
		log.SetOutput(os.Stdout)
		if *api == "" || *clientID == 0 || *siteID == 0 || *token == "" {
			installUsage()
			return
		}
		a.Install(&agent.Installer{
			RMM:         *api,
			ClientID:    *clientID,
			SiteID:      *siteID,
			Description: *desc,
			AgentType:   *atype,
			Power:       *power,
			RDP:         *rdp,
			Ping:        *ping,
			Token:       *token,
			LocalMesh:   *localMesh,
			Cert:        *cert,
			Timeout:     *timeout,
			NoSalt:      *nosalt,
			Silent:      *silent,
		})
	default:
		agent.ShowStatus(version)
	}
}

func setupLogging(level, to *string) {
	ll, err := logrus.ParseLevel(*level)
	if err != nil {
		ll = logrus.InfoLevel
	}
	log.SetLevel(ll)

	if *to == "stdout" {
		log.SetOutput(os.Stdout)
	} else {
		switch runtime.GOOS {
		case "windows":
			logFile, _ = os.OpenFile(filepath.Join(os.Getenv("ProgramFiles"), "TacticalAgent", "agent.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		case "linux":
			// todo
		}
		log.SetOutput(logFile)
	}
}

func installUsage() {
	switch runtime.GOOS {
	case "windows":
		u := `Usage: tacticalrmm.exe -m install -api <https://api.example.com> -client-id X -site-id X -auth <TOKEN>`
		fmt.Println(u)
	case "linux":
		// todo
	}
}

func updateUsage() {
	u := `Usage: tacticalrmm.exe -m update -updateurl https://example.com/winagent-vX.X.X.exe -inno winagent-vX.X.X.exe -updatever 1.1.1`
	fmt.Println(u)
}
