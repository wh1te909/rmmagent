//go:generate goversioninfo -64
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
	version = "1.0.0"
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
	localSalt := flag.String("local-salt", "", "Path to salt executable")
	localMesh := flag.String("local-mesh", "", "Path to mesh executable")
	cert := flag.String("cert", "", "Path to domain CA .pem")
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
	case "updatesalt":
		a.UpdateSalt()
	case "fixsalt": // deprecated, will be removed in future release
		return
	case "taskrunner":
		if len(os.Args) < 5 || *taskPK == 0 {
			return
		}
		a.RunTask(*taskPK)
	case "install":
		log.SetOutput(os.Stdout)
		if *api == "" || *clientID == 0 || *siteID == 0 || *token == "" {
			installUsage()
			return
		}
		i := &agent.Installer{
			RMM:         *api,
			ClientID:    *clientID,
			SiteID:      *siteID,
			Description: *desc,
			AgentType:   *atype,
			Power:       *power,
			RDP:         *rdp,
			Ping:        *ping,
			Token:       *token,
			LocalSalt:   *localSalt,
			LocalMesh:   *localMesh,
			Cert:        *cert,
			Timeout:     *timeout,
		}
		a.Install(i)
	default:
		agent.ShowStatus(version)
	}
}

func setupLogging(level *string, to *string) {
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
