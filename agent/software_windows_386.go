package agent

import (
	"fmt"
	"strings"
	"time"

	so "github.com/iamacarpet/go-win64api/shared"
	"golang.org/x/sys/windows/registry"
)

// GetProgramVersion loops through the registry for software
// and if found, returns its version
func (a *WindowsAgent) GetProgramVersion(name string) string {
	sw, err := InstalledSoftwareList()
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

func InstalledSoftwareList() ([]so.Software, error) {
	sw32, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32")
	if err != nil {
		return nil, err
	}

	return sw32, nil
}

// https://github.com/iamacarpet/go-win64api/blob/master/software.go
func getSoftwareList(baseKey string, arch string) ([]so.Software, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("Error reading from registry: %s", err.Error())
	}
	defer k.Close()

	swList := make([]so.Software, 0)

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("Error reading subkey list from registry: %s", err.Error())
	}
	for _, sw := range subkeys {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey+`\`+sw, registry.QUERY_VALUE)
		if err != nil {
			return nil, fmt.Errorf("Error reading from registry (subkey %s): %s", sw, err.Error())
		}

		dn, _, err := sk.GetStringValue("DisplayName")
		if err == nil {
			swv := so.Software{DisplayName: dn, Arch: arch}

			dv, _, err := sk.GetStringValue("DisplayVersion")
			if err == nil {
				swv.DisplayVersion = dv
			}

			pub, _, err := sk.GetStringValue("Publisher")
			if err == nil {
				swv.Publisher = pub
			}

			id, _, err := sk.GetStringValue("InstallDate")
			if err == nil {
				swv.InstallDate, _ = time.Parse("20060102", id)
			}

			es, _, err := sk.GetIntegerValue("EstimatedSize")
			if err == nil {
				swv.EstimatedSize = es
			}

			cont, _, err := sk.GetStringValue("Contact")
			if err == nil {
				swv.Contact = cont
			}

			hlp, _, err := sk.GetStringValue("HelpLink")
			if err == nil {
				swv.HelpLink = hlp
			}

			isource, _, err := sk.GetStringValue("InstallSource")
			if err == nil {
				swv.InstallSource = isource
			}

			ilocaction, _, err := sk.GetStringValue("InstallLocation")
			if err == nil {
				swv.InstallLocation = ilocaction
			}

			ustring, _, err := sk.GetStringValue("UninstallString")
			if err == nil {
				swv.UninstallString = ustring
			}

			mver, _, err := sk.GetIntegerValue("VersionMajor")
			if err == nil {
				swv.VersionMajor = mver
			}

			mnver, _, err := sk.GetIntegerValue("VersionMinor")
			if err == nil {
				swv.VersionMinor = mnver
			}

			swList = append(swList, swv)
		}
	}

	return swList, nil
}
