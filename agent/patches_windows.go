package agent

import (
	"fmt"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	rmm "github.com/wh1te909/rmmagent/shared"
)

func (a *WindowsAgent) GetWinUpdates(nc *nats.Conn) {
	updates, err := WUAUpdates("IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0")
	if err != nil {
		a.Logger.Errorln(err)
		return
	}

	payload := rmm.WinUpdateResult{AgentID: a.AgentID, Updates: updates}
	var resp []byte
	ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))
	ret.Encode(payload)
	nc.PublishRequest(a.AgentID, "getwinupdates", resp)
}

func (a *WindowsAgent) InstallUpdates(nc *nats.Conn, guids []string) {
	session, err := NewUpdateSession()
	if err != nil {
		a.Logger.Errorln(err)
		return
	}
	defer session.Close()

	for _, id := range guids {
		var resp []byte
		ret := codec.NewEncoderBytes(&resp, new(codec.MsgpackHandle))

		var result rmm.WinUpdateInstallResult
		result.AgentID = a.AgentID
		result.UpdateID = id

		query := fmt.Sprintf("UpdateID='%s'", id)
		a.Logger.Debugln("query:", query)
		updts, err := session.GetWUAUpdateCollection(query)
		if err != nil {
			a.Logger.Errorln(err)
			result.Success = false
			ret.Encode(result)
			nc.PublishRequest(a.AgentID, "winupdateresult", resp)
			continue
		}
		defer updts.Release()

		a.Logger.Debugln("updts:", updts)
		updtCnt, err := updts.Count()
		if err != nil {
			a.Logger.Errorln(err)
			result.Success = false
			ret.Encode(result)
			nc.PublishRequest(a.AgentID, "winupdateresult", resp)
			continue
		}
		a.Logger.Debugln("updtCnt:", updtCnt)

		if updtCnt == 0 {
			result.Success = false
			ret.Encode(result)
			nc.PublishRequest(a.AgentID, "winupdateresult", resp)
			continue
		}

		for i := 0; i < int(updtCnt); i++ {
			u, err := updts.Item(i)
			if err != nil {
				a.Logger.Errorln(err)
				result.Success = false
				ret.Encode(result)
				nc.PublishRequest(a.AgentID, "winupdateresult", resp)
				continue
			}
			a.Logger.Debugln("u:", u)
			err = session.InstallWUAUpdate(u)
			if err != nil {
				a.Logger.Errorln(err)
				result.Success = false
				ret.Encode(result)
				nc.PublishRequest(a.AgentID, "winupdateresult", resp)
				continue
			}
			result.Success = true
			ret.Encode(result)
			nc.PublishRequest(a.AgentID, "winupdateresult", resp)
			a.Logger.Debugln("Installed windows update with guid", id)
		}
	}

	time.Sleep(5 * time.Second)
	needsReboot, err := a.SystemRebootRequired()
	if err != nil {
		a.Logger.Errorln(err)
	}

	var resp2 []byte
	ret2 := codec.NewEncoderBytes(&resp2, new(codec.MsgpackHandle))
	rebootPayload := rmm.AgentNeedsReboot{AgentID: a.AgentID, NeedsReboot: needsReboot}
	ret2.Encode(rebootPayload)
	nc.PublishRequest(a.AgentID, "needsreboot", resp2)
}
