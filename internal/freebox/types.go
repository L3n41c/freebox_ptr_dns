// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import "encoding/json"

// envelope is the common response shape for /api/v4/... endpoints.
type envelope struct {
	Success   bool            `json:"success"`
	Result    json.RawMessage `json:"result,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
	Msg       string          `json:"msg,omitempty"`
}

type authorizeRequest struct {
	AppID      string `json:"app_id"`
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
	DeviceName string `json:"device_name"`
}

type authorizeResult struct {
	AppToken string `json:"app_token"`
	TrackID  int    `json:"track_id"`
}

type authorizeStatusResult struct {
	Status string `json:"status"`
}

type loginResult struct {
	Challenge string `json:"challenge"`
}

type sessionRequest struct {
	AppID    string `json:"app_id"`
	Password string `json:"password"`
}

type sessionResult struct {
	SessionToken string `json:"session_token"`
}

// LanInterface is one of the "browsable" LAN interfaces returned by
// GET /api/v4/lan/browser/interfaces/.
type LanInterface struct {
	Name      string `json:"name"`
	HostCount int    `json:"host_count"`
}

// L3Conn is one (Layer-3) address attached to a LanHost.
type L3Conn struct {
	Addr              string `json:"addr"`
	Af                string `json:"af"` // "ipv4" / "ipv6"
	Active            bool   `json:"active"`
	Reachable         bool   `json:"reachable"`
	LastTimeReachable int64  `json:"last_time_reachable"`
}

// LanHost is one device known by the Freebox on a given interface.
type LanHost struct {
	ID               string   `json:"id"`
	PrimaryName      string   `json:"primary_name"`
	HostType         string   `json:"host_type"`
	Active           bool     `json:"active"`
	Reachable        bool     `json:"reachable"`
	Persistent       bool     `json:"persistent"`
	L3Connectivities []L3Conn `json:"l3connectivities"`
}
