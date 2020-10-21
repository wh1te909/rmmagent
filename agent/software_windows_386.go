package agent

import (
	"strings"

	so "github.com/iamacarpet/go-win64api/shared"
	wapf "github.com/wh1te909/go-win64api"
)

// GetProgramVersion loops through the registry for software
// and if found, returns its version
func (a *WindowsAgent) GetProgramVersion(name string) string {
	sw, err := installedSoftwareList()
	if err != nil {
		a.Logger.Debugf("%s\r\n", err.Error())
		return "0.0.0"
	}

	var lowerName string
	for _, s := range sw {
		lowerName = strings.ToLower(s.Name())
		if strings.Contains(lowerName, name) {
			return s.Version()
		}
	}
	return "0.0.0"
}

func installedSoftwareList() ([]so.Software, error) {
	sw32, err := wapf.GetSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32")
	if err != nil {
		return nil, err
	}

	return sw32, nil
}
