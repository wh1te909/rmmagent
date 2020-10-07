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
)

var client = resty.New()

// APIRequest struct
type APIRequest struct {
	URL       string
	Method    string
	Payload   interface{}
	Headers   map[string]string
	Timeout   time.Duration
	LocalCert string
}

// MakeRequest creates an api request to the RMM
func MakeRequest(r *APIRequest) (*resty.Response, error) {
	client.SetCloseConnection(true)
	client.SetHeaders(r.Headers)
	client.SetTimeout(r.Timeout * time.Second)

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
func PublicIP() string {
	client.SetCloseConnection(true)
	client.SetTimeout(7 * time.Second)
	urls := []string{"https://ifconfig.co/ip", "https://icanhazip.com"}

	for _, url := range urls {
		r, err := client.R().Get(url)
		if err != nil {
			continue
		}
		ip := StripAll(r.String())
		if !IsValidIP(ip) {
			continue
		}
		return ip
	}
	return "error"
}

// GenerateAgentID creates and returns a unique agent id
func GenerateAgentID(hostname string) string {
	rand.Seed(time.Now().UnixNano())
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 35)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b) + "-" + hostname
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
func TotalRAM() float64 {
	host, _ := ps.Host()
	mem, _ := host.Memory()
	return math.Ceil(float64(mem.Total) / 1073741824.0)
}

// BootTime returns system boot time as a unix timestamp
func BootTime() int64 {
	host, _ := ps.Host()
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
