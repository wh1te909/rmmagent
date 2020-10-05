package agent

// Host struct
type Host struct {
	Hostname string `json:"hostname"`
	Arch     string `json:"arch"`
	Timezone string `json:"timezone"`
}

// DB sqlite database stores RMM and agent info
type DB struct {
	Server     string
	AgentID    string
	MeshNodeID string
	Token      string
	AgentPK    int32
	SaltMaster string
	SaltID     string
	Cert       string
}
