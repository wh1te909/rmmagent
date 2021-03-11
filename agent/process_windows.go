package agent

import (
	"fmt"

	ps "github.com/elastic/go-sysinfo"
	gops "github.com/shirou/gopsutil/v3/process"
)

type ProcessMsg struct {
	Name     string `json:"name"`
	Pid      int    `json:"pid"`
	MemBytes uint64 `json:"membytes"`
	Username string `json:"username"`
	UID      int    `json:"id"`
	CPU      string `json:"cpu_percent"`
}

func (a *WindowsAgent) GetProcsRPC() []ProcessMsg {
	ret := make([]ProcessMsg, 0)

	procs, _ := ps.Processes()
	for i, process := range procs {
		p, err := process.Info()
		if err != nil {
			continue
		}
		if p.PID == 0 {
			continue
		}

		m, _ := process.Memory()
		proc, gerr := gops.NewProcess(int32(p.PID))
		if gerr != nil {
			continue
		}
		cpu, _ := proc.CPUPercent()
		user, _ := proc.Username()

		ret = append(ret, ProcessMsg{
			Name:     p.Name,
			Pid:      p.PID,
			MemBytes: m.Resident,
			Username: user,
			UID:      i,
			CPU:      fmt.Sprintf("%.1f", cpu),
		})
	}
	return ret
}

// ChecksRunning prevents duplicate checks from running
// Have to do it this way, can't use atomic because they can run from both rpc and tacticalagent services
func (a *WindowsAgent) ChecksRunning() bool {
	running := false
	procs, err := ps.Processes()
	if err != nil {
		return running
	}

Out:
	for _, process := range procs {
		p, err := process.Info()
		if err != nil {
			continue
		}
		if p.PID == 0 {
			continue
		}
		if p.Exe != a.EXE {
			continue
		}

		for _, arg := range p.Args {
			if arg == "runchecks" || arg == "checkrunner" {
				running = true
				break Out
			}
		}
	}
	return running
}

// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
func ByteCountSI(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}
