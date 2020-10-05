package main

// cross compile from linux for windows
// apt install build-essential gcc-multilib gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
// 64 bit: CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOOS=windows GOARCH=amd64 go build -o tacticalrmm.exe
// 32 bit: CGO_ENABLED=1 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ GOOS=windows GOARCH=386 go build -o tacticalrmm-x86.exe

// building 32 bit from windows from git bash
// env CGO_ENABLED=1 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ GOARCH=386 go build -o tacticalrmm-x86.exe

import (
	"flag"
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
	ver := flag.Bool("version", false, "Prints version")
	mode := flag.String("m", "", "The mode to run")
	logLevel := flag.String("log", "INFO", "The log level")
	logTo := flag.String("logto", "file", "Where to log to")
	flag.Parse()

	if *ver {
		agent.ShowVersionInfo(version)
		return
	}

	if len(os.Args) == 1 {
		// TODO show agent status
		return
	}

	setupLogging(logLevel, logTo)
	defer logFile.Close()

	a := *agent.New(log, version)

	switch *mode {
	case "install":
		log.SetOutput(os.Stdout)
		// TODO
		return
	case "winagentsvc":
		a.RunAsService()
	default:
		// TODO
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
