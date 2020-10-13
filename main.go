//go:generate goversioninfo -64
package main

// cross compile from linux for windows
// apt install build-essential gcc-multilib gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
// 64 bit: CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOOS=windows GOARCH=amd64 go build -o tacticalrmm.exe
// 32 bit: CGO_ENABLED=1 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ GOOS=windows GOARCH=386 go build -o tacticalrmm-x86.exe

// building 32 bit from windows from git bash
// env CGO_ENABLED=1 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ GOARCH=386 go build -o tacticalrmm-x86.exe

import (
	"flag"
	"fmt"
	"os"

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
	logLevel := flag.String("log", "INFO", "The log level")
	logTo := flag.String("logto", "file", "Where to log to")
	api := flag.String("api", "", "API URL")
	clientID := flag.Int("client-id", 0, "Client ID")
	siteID := flag.Int("site-id", 0, "Site ID")
	timeout := flag.Duration("timeout", 900, "Installer timeout (seconds)")
	desc := flag.String("desc", hostname, "Agent's Description")
	atype := flag.String("agent-type", "server", "Server or Workstation")
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
		agent.ShowStatus()
		return
	}

	setupLogging(logLevel, logTo)
	defer logFile.Close()

	a := *agent.New(log, version)

	switch *mode {
	case "checkrunner":
		a.CheckRunner()
	case "winagentsvc":
		a.RunAsService()
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
		agent.ShowStatus()
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
		logFile, _ = os.OpenFile("agent.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		log.SetOutput(logFile)
	}
}

func installUsage() {
	u := `Usage: tacticalrmm.exe -m install -api <https://api.example.com> -client-id X -site-id X -auth <TOKEN>`
	fmt.Println(u)
}
