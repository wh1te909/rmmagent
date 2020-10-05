package agent

import (
	"strings"

	wapi "github.com/iamacarpet/go-win64api"
)

// GetProgramVersion loops through the registry for software
// and if found, returns its version
func (a *WindowsAgent) GetProgramVersion(name string) string {
	sw, err := wapi.InstalledSoftwareList()
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
