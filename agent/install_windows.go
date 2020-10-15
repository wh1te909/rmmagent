package agent

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gonutz/w32"
)

type Installer struct {
	Headers     map[string]string
	RMM         string
	ClientID    int
	SiteID      int
	Description string
	AgentType   string
	Power       bool
	RDP         bool
	Ping        bool
	Token       string
	LocalSalt   string
	LocalMesh   string
	Cert        string
	Timeout     time.Duration
	SaltMaster  string
}

func (a *WindowsAgent) Install(i *Installer) {
	a.checkExistingAndRemove()

	i.Headers = map[string]string{
		"content-type":  "application/json",
		"Authorization": fmt.Sprintf("Token %s", i.Token),
	}
	a.AgentID = GenerateAgentID(a.Hostname)
	a.Logger.Debugln("Agent ID:", a.AgentID)

	u, err := url.Parse(i.RMM)
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		a.installerMsg("Invalid URL (must contain https or http)", "error")
	}

	i.SaltMaster = u.Host
	a.Logger.Debugln("Salt Master:", i.SaltMaster)

	baseURL := u.Scheme + "://" + u.Host
	a.Logger.Debugln("Base URL:", baseURL)

	minion := filepath.Join(a.ProgramDir, a.SaltInstaller)
	a.Logger.Debugln("Salt Minion:", minion)

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(i.Timeout * time.Second)
	//rClient.SetDebug(a.Debug)

	// download or copy the salt-minion-setup.exe
	saltMin := filepath.Join(a.ProgramDir, a.SaltInstaller)
	if i.LocalSalt == "" {
		a.Logger.Infoln("Downloading salt minion...")
		a.Logger.Debugln("Downloading from:", a.SaltMinion)
		r, err := rClient.R().SetOutput(saltMin).Get(a.SaltMinion)
		if err != nil {
			a.installerMsg(fmt.Sprintf("Unable to download salt minion: %s", err.Error()), "error")
		}
		if r.StatusCode() != 200 {
			a.installerMsg(fmt.Sprintf("Unable to download salt minion from %s", a.SaltMinion), "error")
		}

	} else {
		err := copyFile(i.LocalSalt, saltMin)
		if err != nil {
			a.installerMsg(err.Error(), "error")
		}
	}

	// set rest knox headers
	rClient.SetHeaders(i.Headers)

	// set local cert if applicable
	if len(i.Cert) > 0 {
		if !FileExists(i.Cert) {
			a.installerMsg(fmt.Sprintf("%s does not exist", i.Cert), "error")
		}
		rClient.SetRootCertificate(i.Cert)
	}

	var arch string
	switch a.Arch {
	case "x86_64":
		arch = "64"
	case "x86":
		arch = "32"
	}

	// download or copy the mesh-agent.exe
	mesh := filepath.Join(a.ProgramDir, a.MeshInstaller)
	if i.LocalMesh == "" {
		a.Logger.Infoln("Downloading mesh agent...")
		payload := map[string]string{"arch": arch}
		r, err := rClient.R().SetBody(payload).SetOutput(mesh).Post(fmt.Sprintf("%s/api/v2/meshexe/", baseURL))
		if err != nil {
			a.installerMsg(fmt.Sprintf("Failed to download mesh agent: %s", err.Error()), "error")
		}
		if r.StatusCode() != 200 {
			a.installerMsg(fmt.Sprintf("Unable to download the mesh agent from the RMM. %s", r.String()), "error")
		}
	} else {
		err := copyFile(i.LocalSalt, saltMin)
		if err != nil {
			a.installerMsg(err.Error(), "error")
		}
	}

	// get agent's token
	type TokenResp struct {
		Token string `json:"token"`
	}
	payload := map[string]string{"agent_id": a.AgentID}
	r, err := rClient.R().SetBody(payload).SetResult(&TokenResp{}).Post(fmt.Sprintf("%s/api/v2/newagent/", baseURL))
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}
	if r.StatusCode() != 200 {
		a.installerMsg(r.String(), "error")
	}

	agentToken := r.Result().(*TokenResp).Token

	a.Logger.Infoln("Installing mesh agent...")
	a.Logger.Debugln("Mesh agent:", mesh)
	meshOut, meshErr := CMD(mesh, []string{"-fullinstall"}, int(60), false)
	if meshErr != nil {
		a.installerMsg(fmt.Sprintf("Failed to install mesh agent: %s", meshErr.Error()), "error")
	}
	if meshOut[1] != "" {
		a.installerMsg(fmt.Sprintf("Failed to install mesh agent: %s", meshOut[1]), "error")
	}

	fmt.Println(meshOut)

	a.Logger.Debugln("Waiting for mesh service to be running")
	WaitForService(a.MeshSVC, "running", 15)
	a.Logger.Debugln("Mesh service is running")
	a.Logger.Debugln("Sleeping for 10")
	time.Sleep(10 * time.Second)

	meshSuccess := false
	var meshNodeID string
	for !meshSuccess {
		a.Logger.Debugln("Getting mesh node id hex")
		pMesh, pErr := CMD(mesh, []string{"-nodeidhex"}, int(30), false)
		if pErr != nil {
			a.Logger.Errorln(pErr)
			time.Sleep(5 * time.Second)
			continue
		}
		if pMesh[1] != "" {
			a.Logger.Errorln(pMesh[1])
			time.Sleep(5 * time.Second)
			continue
		}
		meshNodeID = StripAll(pMesh[0])
		a.Logger.Debugln("Node id hex:", meshNodeID)
		if strings.Contains(strings.ToLower(meshNodeID), "not defined") {
			a.Logger.Errorln(meshNodeID)
			time.Sleep(5 * time.Second)
			continue
		}
		meshSuccess = true
	}

	a.Logger.Infoln("Adding agent to dashboard")
	// add agent
	type NewAgentResp struct {
		AgentPK int    `json:"pk"`
		SaltID  string `json:"saltid"`
	}
	agentPayload := map[string]interface{}{
		"agent_id":        a.AgentID,
		"hostname":        a.Hostname,
		"client":          i.ClientID,
		"site":            i.SiteID,
		"mesh_node_id":    meshNodeID,
		"description":     i.Description,
		"monitoring_type": i.AgentType,
	}

	r, err = rClient.R().SetBody(agentPayload).SetResult(&NewAgentResp{}).Patch(fmt.Sprintf("%s/api/v2/newagent/", baseURL))
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}
	if r.StatusCode() != 200 {
		a.installerMsg(r.String(), "error")
	}

	agentPK := r.Result().(*NewAgentResp).AgentPK
	saltID := r.Result().(*NewAgentResp).SaltID

	a.Logger.Debugln("Agent token:", agentToken)
	a.Logger.Debugln("Agent PK:", agentPK)
	a.Logger.Debugln("Salt ID:", saltID)

	// create the database
	db, err := sql.Open("sqlite3", filepath.Join(a.ProgramDir, "agentdb.db"))
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}
	defer db.Close()

	sqlStmt := `
	CREATE TABLE "agentstorage" ("id" INTEGER NOT NULL PRIMARY KEY, "server" VARCHAR(255) NOT NULL, "agentid" VARCHAR(255) NOT NULL, "mesh_node_id" VARCHAR(255) NOT NULL, "token" VARCHAR(255) NOT NULL, "agentpk" INTEGER NOT NULL, "salt_master" VARCHAR(255) NOT NULL, "salt_id" VARCHAR(255) NOT NULL, "cert" VARCHAR(255));
	`

	_, err = db.Exec(sqlStmt)
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}

	tx, err := db.Begin()
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}

	stmt, err := tx.Prepare("insert into agentstorage(id, server, agentid, mesh_node_id, token, agentpk, salt_master, salt_id, cert) values(?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		a.installerMsg(err.Error(), "error")
	}
	defer stmt.Close()

	if len(i.Cert) > 0 {
		_, err = stmt.Exec(1, baseURL, a.AgentID, meshNodeID, agentToken, agentPK, i.SaltMaster, saltID, i.Cert)
	} else {
		_, err = stmt.Exec(1, baseURL, a.AgentID, meshNodeID, agentToken, agentPK, i.SaltMaster, saltID, nil)
	}

	if err != nil {
		a.installerMsg(err.Error(), "error")
	}
	tx.Commit()
	db.Close()

	// refresh our agent with new values
	a = New(a.Logger, a.Version)

	// install salt
	a.Logger.Debugln("changing dir to", a.ProgramDir)
	cdErr := os.Chdir(a.ProgramDir)
	if cdErr != nil {
		a.installerMsg(cdErr.Error(), "error")
	}

	a.Logger.Infoln("Installing the salt-minion, this might take a while...")
	saltInstallArgs := []string{
		a.SaltInstaller,
		"/S",
		"/custom-config=saltcustom",
		fmt.Sprintf("/master=%s", i.SaltMaster),
		fmt.Sprintf("/minion-name=%s", saltID),
		"/start-minion=1",
	}

	a.Logger.Debugln("Installing salt with:", saltInstallArgs)
	_, saltErr := CMDShell(saltInstallArgs, "", int(i.Timeout), false)
	if saltErr != nil {
		a.installerMsg(fmt.Sprintf("Unable to install salt: %s", saltErr.Error()), "error")
	}

	a.Logger.Debugln("Waiting for salt-minion service enter the running state")
	WaitForService("salt-minion", "running", 30)
	a.Logger.Debugln("Salt-minion is running")
	_, serr := WinServiceGet("salt-minion")
	if serr != nil {
		a.installerMsg("Salt installation failed\nCheck the log file in c:\\salt\\var\\log\\salt\\minion", "error")
	}

	time.Sleep(5 * time.Second)

	// set new headers, no longer knox auth...use agent auth
	rClient.SetHeaders(a.Headers)

	// accept the salt key on the rmm
	a.Logger.Debugln("Registering salt with the RMM")
	acceptPayload := map[string]string{"saltid": saltID, "agent_id": a.AgentID}
	acceptAttempts := 0
	acceptRetries := 20
	for {
		r, err := rClient.R().SetBody(acceptPayload).Post(fmt.Sprintf("%s/api/v2/saltminion/", baseURL))
		if err != nil {
			a.Logger.Debugln(err)
			acceptAttempts++
			time.Sleep(5 * time.Second)
		}

		if r.StatusCode() != 200 {
			a.Logger.Debugln(r.String())
			acceptAttempts++
			time.Sleep(5 * time.Second)
		} else {
			acceptAttempts = 0
		}

		if acceptAttempts == 0 {
			a.Logger.Debugln(r.String())
			break
		} else if acceptAttempts >= acceptRetries {
			a.installerMsg("Unable to register salt with the RMM\nInstallation failed.", "error")
		}
	}

	time.Sleep(10 * time.Second)

	// sync salt modules
	a.Logger.Debugln("Syncing salt modules")
	syncPayload := map[string]string{"agent_id": a.AgentID}
	syncAttempts := 0
	syncRetries := 20
	for {
		r, err := rClient.R().SetBody(syncPayload).Patch(fmt.Sprintf("%s/api/v2/saltminion/", baseURL))
		if err != nil {
			a.Logger.Debugln(err)
			syncAttempts++
			time.Sleep(5 * time.Second)
		}

		if r.StatusCode() != 200 {
			a.Logger.Debugln(r.String())
			syncAttempts++
			time.Sleep(5 * time.Second)
		} else {
			syncAttempts = 0
		}

		if syncAttempts == 0 {
			a.Logger.Debugln(r.String())
			break
		} else if syncAttempts >= syncRetries {
			a.installerMsg("Unable to sync salt modules\nInstallation failed.", "error")
		}
	}

	// send wmi sysinfo
	a.Logger.Debugln("Getting sysinfo with WMI")
	a.GetWMI()

	// remove existing services if exist
	services := []string{"tacticalagent", "checkrunner"}
	for _, svc := range services {
		_, err := WinServiceGet(svc)
		if err == nil {
			a.Logger.Debugln(fmt.Sprintf("Found existing %s service. Removing", svc))
			_, _ = CMD(a.Nssm, []string{"stop", svc}, 30, false)
			_, _ = CMD(a.Nssm, []string{"remove", svc, "confirm"}, 30, false)
		}
	}

	a.Logger.Infoln("Installing services...")
	svcCommands := [8][]string{
		// winagentsvc
		{"install", "tacticalagent", a.EXE, "-m", "winagentsvc"},
		{"set", "tacticalagent", "DisplayName", "Tactical RMM Agent"},
		{"set", "tacticalagent", "Description", "Tactical RMM Agent"},
		{"start", "tacticalagent"},
		//checkrunner
		{"install", "checkrunner", a.EXE, "-m", "checkrunner"},
		{"set", "checkrunner", "DisplayName", "Tactical RMM Check Runner"},
		{"set", "checkrunner", "Description", "Tactical RMM Check Runner"},
		{"start", "checkrunner"},
	}

	for _, s := range svcCommands {
		a.Logger.Debugln(s)
		_, nssmErr := CMD(a.Nssm, s, 15, false)
		if nssmErr != nil {
			a.installerMsg(nssmErr.Error(), "error")
		}
	}

	if i.Power {
		a.Logger.Infoln("Disabling sleep/hibernate...")
		DisableSleepHibernate()
	}

	if i.Ping {
		a.Logger.Infoln("Enabling ping...")
		EnablePing()
	}

	if i.RDP {
		a.Logger.Infoln("Enabling RDP...")
		EnableRDP()
	}

	a.installerMsg("Installation was successfull!\nAllow a few minutes for the agent to properly display in the RMM", "info")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return nil
}

func (a *WindowsAgent) checkExistingAndRemove() {
	installedMesh := filepath.Join(a.ProgramDir, "Mesh Agent", "MeshAgent.exe")
	installedSalt := filepath.Join(a.SystemDrive, "\\salt", "uninst.exe")
	agentDB := filepath.Join(a.ProgramDir, "agentdb.db")
	if FileExists(installedMesh) || FileExists(installedSalt) || FileExists(agentDB) {
		tacUninst := filepath.Join(a.ProgramDir, "unins000.exe")
		tacUninstArgs := []string{tacUninst, "/VERYSILENT", "/SUPPRESSMSGBOXES"}

		window := w32.GetForegroundWindow()
		if window != 0 {
			var handle w32.HWND
			msg := "Existing installation found\nClick OK to remove, then re-run the installer.\nClick Cancel to abort."
			action := w32.MessageBox(handle, msg, "Tactical RMM", w32.MB_OKCANCEL|w32.MB_ICONWARNING)
			if action == w32.IDOK {
				_, _ = CMDShell(tacUninstArgs, "", 60, true)
			}
		} else {
			fmt.Println("Existing installation found and must be removed before attempting to reinstall.")
			fmt.Println("Run the following command to uninstall, and then re-run this installer.")
			fmt.Printf("\"%s\" %s %s", tacUninstArgs[0], tacUninstArgs[1], tacUninstArgs[2])
		}
		os.Exit(0)
	}
}
