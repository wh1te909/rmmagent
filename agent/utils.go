package agent

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ps "github.com/elastic/go-sysinfo"
	"github.com/go-resty/resty/v2"
	"github.com/shirou/gopsutil/v3/process"
)

// APIRequest struct
type APIRequest struct {
	URL       string
	Method    string
	Payload   interface{}
	Headers   map[string]string
	Timeout   time.Duration
	LocalCert string
	Debug     bool
}

// MakeRequest creates an api request to the RMM
func (r APIRequest) MakeRequest() (*resty.Response, error) {
	client := resty.New()
	client.SetCloseConnection(true)
	client.SetHeaders(r.Headers)
	client.SetTimeout(r.Timeout * time.Second)
	client.SetDebug(r.Debug)

	if len(r.LocalCert) > 0 {
		client.SetRootCertificate(r.LocalCert)
	}

	var resp *resty.Response
	var err error

	switch r.Method {
	case "GET":
		resp, err = client.R().Get(r.URL)
	case "POST":
		resp, err = client.R().SetBody(r.Payload).Post(r.URL)
	case "PATCH":
		resp, err = client.R().SetBody(r.Payload).Patch(r.URL)
	case "PUT":
		resp, err = client.R().SetBody(r.Payload).Put(r.URL)
	}

	if err != nil {
		return &resty.Response{}, err
	}
	return resp, nil
}

// PublicIP returns the agent's public ip
// Tries 2 times before giving up
func (a *WindowsAgent) PublicIP() string {
	a.Logger.Debugln("PublicIP start")
	client := resty.New()
	client.SetCloseConnection(true)
	client.SetTimeout(7 * time.Second)
	urls := []string{"https://icanhazip.com", "https://ifconfig.co/ip"}

	for _, url := range urls {
		r, err := client.R().Get(url)
		if err != nil {
			a.Logger.Debugln("PublicIP err", err)
			continue
		}
		ip := StripAll(r.String())
		if !IsValidIP(ip) {
			a.Logger.Debugln("PublicIP not valid", ip)
			continue
		}
		a.Logger.Debugln("PublicIP return: ", ip)
		return ip
	}
	return "error"
}

// GenerateAgentID creates and returns a unique agent id
func GenerateAgentID() string {
	rand.Seed(time.Now().UnixNano())
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 40)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// ShowVersionInfo prints basic debugging info
func ShowVersionInfo(ver string) {
	fmt.Println("Tactical RMM Agent:", ver)
	fmt.Println("Arch:", runtime.GOARCH)
	fmt.Println("Go version:", runtime.Version())
	if runtime.GOOS == "windows" {
		fmt.Println("Program Directory:", filepath.Join(os.Getenv("ProgramFiles"), "TacticalAgent"))
	}
}

// FileExists checks whether a file exists
func FileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// TotalRAM returns total RAM in GB
func (a *WindowsAgent) TotalRAM() float64 {
	host, err := ps.Host()
	if err != nil {
		return 8.0
	}
	mem, err := host.Memory()
	if err != nil {
		return 8.0
	}
	return math.Ceil(float64(mem.Total) / 1073741824.0)
}

// BootTime returns system boot time as a unix timestamp
func (a *WindowsAgent) BootTime() int64 {
	host, err := ps.Host()
	if err != nil {
		return 1000
	}
	info := host.Info()
	return info.BootTime.Unix()
}

// IsValidIP checks for a valid ipv4 or ipv6
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// StripAll strips all whitespace and newline chars
func StripAll(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\n")
	s = strings.Trim(s, "\r")
	return s
}

// KillProc kills a process and its children
func KillProc(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}

	children, err := p.Children()
	if err == nil {
		for _, child := range children {
			if err := child.Kill(); err != nil {
				continue
			}
		}
	}

	if err := p.Kill(); err != nil {
		return err
	}
	return nil
}

// DjangoStringResp removes double quotes from django rest api resp
func DjangoStringResp(resp string) string {
	return strings.Trim(resp, `"`)
}

func TestTCP(addr string) error {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}
