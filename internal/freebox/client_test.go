// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer is a tiny stand-in for the Freebox API used to drive tests.
type fakeServer struct {
	t      *testing.T
	server *httptest.Server

	mu         sync.Mutex
	challenge  string
	token      string // current valid session token
	appToken   string
	grants     int32 // sessionRequest invocation count
	hostsResp  []LanHost
	ifaceResp  []LanInterface
	trackID    int
	trackState string // "pending", "granted", "denied", "timeout"
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		t:          t,
		challenge:  "challenge-A",
		token:      "session-token-1",
		appToken:   "app-token-secret",
		trackID:    42,
		trackState: "granted",
	}
	fs.server = httptest.NewServer(http.HandlerFunc(fs.handle))
	t.Cleanup(fs.server.Close)
	return fs
}

func (fs *fakeServer) get() (challenge, token, appToken, trackState string, hostsResp []LanHost, ifaceResp []LanInterface) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.challenge, fs.token, fs.appToken, fs.trackState, fs.hostsResp, fs.ifaceResp
}

func (fs *fakeServer) setTrackState(s string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.trackState = s
}

func (fs *fakeServer) setToken(s string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.token = s
}

func (fs *fakeServer) setHosts(h []LanHost) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.hostsResp = h
}

func (fs *fakeServer) setIfaces(i []LanInterface) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.ifaceResp = i
}

func (fs *fakeServer) getAppToken() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.appToken
}

func (fs *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	challenge, token, appToken, trackState, hostsResp, ifaceResp := fs.get()

	switch {
	case r.Method == "POST" && r.URL.Path == "/api/v4/login/authorize/":
		var req authorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeOK(w, authorizeResult{AppToken: appToken, TrackID: fs.trackID})

	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v4/login/authorize/"):
		writeOK(w, authorizeStatusResult{Status: trackState})

	case r.Method == "GET" && r.URL.Path == "/api/v4/login/":
		writeOK(w, loginResult{Challenge: challenge})

	case r.Method == "POST" && r.URL.Path == "/api/v4/login/session/":
		atomic.AddInt32(&fs.grants, 1)
		var req sessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mac := hmac.New(sha1.New, []byte(appToken))
		mac.Write([]byte(challenge))
		want := hex.EncodeToString(mac.Sum(nil))
		if req.Password != want {
			writeErr(w, "invalid_token", "bad password")
			return
		}
		writeOK(w, sessionResult{SessionToken: token})

	case r.Method == "GET" && r.URL.Path == "/api/v4/lan/browser/interfaces/":
		if r.Header.Get("X-Fbx-App-Auth") != token {
			writeErr(w, "auth_required", "session expired")
			return
		}
		writeOK(w, ifaceResp)

	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v4/lan/browser/"):
		if r.Header.Get("X-Fbx-App-Auth") != token {
			writeErr(w, "auth_required", "session expired")
			return
		}
		writeOK(w, hostsResp)

	default:
		http.Error(w, "not found: "+r.Method+" "+r.URL.Path, 404)
	}
}

func writeOK(w http.ResponseWriter, result any) {
	b, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Result: b})
}

func writeErr(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200) // Freebox returns 200 + success=false
	_ = json.NewEncoder(w).Encode(envelope{Success: false, ErrorCode: code, Msg: msg})
}

// --- Register flow ----------------------------------------------------------

func TestRegister_HappyPath(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(fs, "")

	tok, err := c.Register(context.Background(), 10*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tok != fs.getAppToken() {
		t.Errorf("got token %q", tok)
	}
}

func TestRegister_Denied(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("denied")
	c := newTestClient(fs, "")

	_, err := c.Register(context.Background(), 10*time.Millisecond, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for denied")
	}
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Errorf("want ErrAuthorizationDenied, got %v", err)
	}
}

func TestRegister_TimeoutFromFreebox(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("timeout")
	c := newTestClient(fs, "")

	_, err := c.Register(context.Background(), 10*time.Millisecond, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for timeout")
	}
	if !errors.Is(err, ErrAuthorizationTimedOut) {
		t.Errorf("want ErrAuthorizationTimedOut, got %v", err)
	}
}

func TestRegister_PendingThenGranted(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("pending")
	c := newTestClient(fs, "")

	go func() {
		time.Sleep(20 * time.Millisecond)
		fs.setTrackState("granted")
	}()

	tok, err := c.Register(context.Background(), 5*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tok != fs.getAppToken() {
		t.Errorf("got token %q", tok)
	}
}

// --- Session refresh --------------------------------------------------------

func TestSession_Refresh(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(fs, fs.getAppToken())

	tok, err := c.sessionToken(context.Background())
	if err != nil {
		t.Fatalf("sessionToken: %v", err)
	}
	if tok != "session-token-1" {
		t.Errorf("got %q", tok)
	}
}

func TestSession_CachedBetweenCalls(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(fs, fs.getAppToken())

	for i := 0; i < 5; i++ {
		if _, err := c.sessionToken(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&fs.grants); got != 1 {
		t.Errorf("session refresh called %d times, want 1", got)
	}
}

func TestSession_RefreshOnAuthRequired(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(fs, fs.getAppToken())

	if _, err := c.ListInterfaces(context.Background()); err != nil {
		t.Fatalf("first ListInterfaces: %v", err)
	}
	// Server rotates session token: previously stored client token now invalid.
	fs.setToken("session-token-2")
	if _, err := c.ListInterfaces(context.Background()); err != nil {
		t.Fatalf("second ListInterfaces: %v", err)
	}
	if got := atomic.LoadInt32(&fs.grants); got != 2 {
		t.Errorf("session refresh called %d times, want 2", got)
	}
}

// --- LAN --------------------------------------------------------------------

func TestListInterfaces(t *testing.T) {
	fs := newFakeServer(t)
	fs.setIfaces([]LanInterface{
		{Name: "pub", HostCount: 3},
		{Name: "ipv6", HostCount: 2},
	})
	c := newTestClient(fs, fs.getAppToken())

	ifaces, err := c.ListInterfaces(context.Background())
	if err != nil {
		t.Fatalf("ListInterfaces: %v", err)
	}
	if len(ifaces) != 2 || ifaces[0].Name != "pub" || ifaces[1].Name != "ipv6" {
		t.Errorf("got %+v", ifaces)
	}
}

func TestListHosts(t *testing.T) {
	fs := newFakeServer(t)
	fs.setHosts([]LanHost{
		{
			ID:          "ether-aa:bb:cc:dd:ee:ff",
			PrimaryName: "laptop",
			Active:      true,
			Reachable:   true,
			L3Connectivities: []L3Conn{
				{Addr: "192.168.1.42", Af: "ipv4", Active: true, Reachable: true},
				{Addr: "fd00::1", Af: "ipv6", Active: true, Reachable: true},
			},
		},
	})
	c := newTestClient(fs, fs.getAppToken())

	hosts, err := c.ListHosts(context.Background(), "pub")
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].PrimaryName != "laptop" {
		t.Fatalf("got %+v", hosts)
	}
	if len(hosts[0].L3Connectivities) != 2 {
		t.Errorf("expected 2 addrs, got %d", len(hosts[0].L3Connectivities))
	}
}

// --- helpers ----------------------------------------------------------------

func newTestClient(fs *fakeServer, appToken string) *Client {
	return NewClient(ClientOptions{
		BaseURL:    fs.server.URL,
		AppID:      "test.app",
		AppName:    "Test App",
		AppVersion: "1.0",
		DeviceName: "host",
		AppToken:   appToken,
		HTTPClient: fs.server.Client(),
	})
}
