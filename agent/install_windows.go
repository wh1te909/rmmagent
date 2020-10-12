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
		a.installerMsg("Invalid URL (must contain https or http)\nInstallation Failed", "error")
	}

	i.SaltMaster = u.Host
	a.Logger.Debugln("Salt Master:", i.SaltMaster)

	baseURL := u.Scheme + "://" + u.Host
	a.Logger.Debugln(baseURL)

	minion := filepath.Join(a.ProgramDir, a.SaltInstaller)
	a.Logger.Debugln("Salt Minion:", minion)

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(i.Timeout * time.Second)
	rClient.SetDebug(a.Debug)

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

	// install mesh agent
	out, err := CMD(mesh, []string{"-fullinstall"}, int(60), false)
	if err != nil {
		a.installerMsg(fmt.Sprintf("Failed to install mesh agent: %s", err.Error()), "error")
	}
	if out[1] != "" {
		a.installerMsg(fmt.Sprintf("Failed to install mesh agent: %s", out[1]), "error")
	}

	WaitForService("mesh agent", "running", 10)
	time.Sleep(10 * time.Second)

	meshSuccess := false
	var meshNodeID string
	for !meshSuccess {
		pMesh, err := CMD(mesh, []string{"-nodeidhex"}, int(30), false)
		if err != nil {
			a.Logger.Errorln(err)
			time.Sleep(5 * time.Second)
			continue
		}
		if out[1] != "" {
			a.Logger.Errorln(out[1])
			time.Sleep(5 * time.Second)
			continue
		}
		meshNodeID = StripAll(pMesh[0])
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

	fmt.Println(agentToken, agentPK, saltID)

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
