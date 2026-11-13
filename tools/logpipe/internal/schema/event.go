package schema

import "time"

type Event struct {
	Event    EventMeta `json:"event"`
	Host     Host      `json:"host"`
	Severity string    `json:"severity"`

	User    *User    `json:"user,omitempty"`
	Process *Process `json:"process,omitempty"`
	Network *Network `json:"network,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

type EventMeta struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Kind   string    `json:"kind"`
}

type Host struct {
	Name string `json:"name"`
}

type User struct {
	Name string `json:"name,omitempty"`
}

type Process struct {
	Name        string `json:"name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
}

type Network struct {
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}
