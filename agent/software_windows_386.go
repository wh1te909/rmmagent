package agent

import (
	"fmt"

	so "github.com/iamacarpet/go-win64api/shared"
	wapf "github.com/wh1te909/go-win64api"
	rmm "github.com/wh1te909/rmmagent/shared"
)

func installedSoftwareList() ([]so.Software, error) {
	sw32, err := wapf.GetSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32")
	if err != nil {
		return nil, err
	}

	return sw32, nil
}

func (a *WindowsAgent) GetInstalledSoftware() []rmm.SoftwareList {
	ret := make([]rmm.SoftwareList, 0)

	sw, err := installedSoftwareList()
	if err != nil {
		return ret
	}

	for _, s := range sw {
		t := s.InstallDate
		ret = append(ret, rmm.SoftwareList{
			Name:        s.Name(),
			Version:     s.Version(),
			Publisher:   s.Publisher,
			InstallDate: fmt.Sprintf("%02d-%d-%02d", t.Year(), t.Month(), t.Day()),
			Size:        ByteCountSI(s.EstimatedSize * 1024),
			Source:      s.InstallSource,
			Location:    s.InstallLocation,
			Uninstall:   s.UninstallString,
		})
	}
	return ret
}
