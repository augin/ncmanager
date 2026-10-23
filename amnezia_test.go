package main

import (
	"strings"
	"testing"
)

const sampleAmneziaConfig = `# AmneziaWG client config
[Interface]
PrivateKey = <server_key_placeholder>
Address = 10.8.0.2/24
Table = off
DNS = 1.1.1.1
MTU = 1380
ListenPort = 51820
JC = 5
JMIN = 30
JMAX = 80
S1 = 11
S2 = 22
S3 = 33
S4 = 44
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = 16
I2 = 32
I3 = 8
I4 = 16
I5 = 4

[Peer]
PublicKey = SERVERPUB
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 35
`

func TestParseAmneziaConfigDefaults(t *testing.T) {
	cfg := parseAmneziaConfig("[Interface]\n[Peer]\n")
	if cfg.MTU != 1420 {
		t.Errorf("default MTU = %d, want 1420", cfg.MTU)
	}
	if cfg.Keepalive != 25 {
		t.Errorf("default Keepalive = %d, want 25", cfg.Keepalive)
	}
	if cfg.JC != 4 || cfg.JMIN != 40 || cfg.JMAX != 70 {
		t.Errorf("defaults JC/JMIN/JMAX = %d/%d/%d, want 4/40/70", cfg.JC, cfg.JMIN, cfg.JMAX)
	}
}

func TestParseAmneziaConfigFull(t *testing.T) {
	cfg := parseAmneziaConfig(sampleAmneziaConfig)

	if cfg.Address != "10.8.0.2/24" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.DNS != "1.1.1.1" {
		t.Errorf("DNS = %q", cfg.DNS)
	}
	if cfg.MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", cfg.MTU)
	}
	if cfg.JC != 5 || cfg.JMIN != 30 || cfg.JMAX != 80 {
		t.Errorf("JC/JMIN/JMAX = %d/%d/%d, want 5/30/80", cfg.JC, cfg.JMIN, cfg.JMAX)
	}
	if cfg.S1 != 11 || cfg.S2 != 22 || cfg.S3 != 33 || cfg.S4 != 44 {
		t.Errorf("S1..S4 = %d/%d/%d/%d, want 11/22/33/44", cfg.S1, cfg.S2, cfg.S3, cfg.S4)
	}
	if cfg.H1 != "1" || cfg.H2 != "2" || cfg.H3 != "3" || cfg.H4 != "4" {
		t.Errorf("H1..H4 = %q/%q/%q/%q", cfg.H1, cfg.H2, cfg.H3, cfg.H4)
	}
	if cfg.I1 != "16" || cfg.I2 != "32" || cfg.I3 != "8" || cfg.I4 != "16" || cfg.I5 != "4" {
		t.Errorf("I1..I5 = %q/%q/%q/%q/%q", cfg.I1, cfg.I2, cfg.I3, cfg.I4, cfg.I5)
	}
	if cfg.PublicKey != "SERVERPUB" {
		t.Errorf("PublicKey = %q", cfg.PublicKey)
	}
	if cfg.AllowedIPs != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %q", cfg.AllowedIPs)
	}
	if cfg.Endpoint != "vpn.example.com:51820" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.Keepalive != 35 {
		t.Errorf("Keepalive = %d, want 35", cfg.Keepalive)
	}
	if cfg.Table != "off" {
		t.Errorf("Table = %q, want off", cfg.Table)
	}
}

func TestParseAmneziaConfigSkipsCommentsAndJunk(t *testing.T) {
	cfg := parseAmneziaConfig("# comment\n// comment2\n\nnot a key value line\nPrivateKey = secret\nListenPort = 12345\n")
	if cfg.MTU != 1420 {
		t.Errorf("junk must not change defaults, MTU = %d", cfg.MTU)
	}
	if cfg.Name != "" || cfg.Endpoint != "" || cfg.PublicKey != "" {
		t.Errorf("PrivateKey/ListenPort/comments must be skipped: %+v", cfg)
	}
}

func TestParseAmneziaConfigIgnoresInvalidNumbers(t *testing.T) {
	cfg := parseAmneziaConfig("MTU = abc\nPersistentKeepalive = xyz\nJC = 9\n")
	if cfg.MTU != 1420 {
		t.Errorf("invalid MTU must keep default, got %d", cfg.MTU)
	}
	if cfg.Keepalive != 25 {
		t.Errorf("invalid keepalive must keep default, got %d", cfg.Keepalive)
	}
	if cfg.JC != 9 {
		t.Errorf("valid JC must be applied, got %d", cfg.JC)
	}
}

func TestWriteAmneziaConfig(t *testing.T) {
	in := parseAmneziaConfig(sampleAmneziaConfig)
	out := writeAmneziaConfig(in)

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = <server_key_placeholder>",
		"Address = 10.8.0.2/24",
		"Table = off",
		"DNS = 1.1.1.1",
		"MTU = 1380",
		"JC = 5",
		"H1 = 1",
		"I5 = 4",
		"[Peer]",
		"PublicKey = SERVERPUB",
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = vpn.example.com:51820",
		"PersistentKeepalive = 35",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("written config must contain %q\ngot:\n%s", want, out)
		}
	}
}

func TestWriteAmneziaConfigListenPortOnlyForServer(t *testing.T) {
	srv := amneziaConfigResponse{Address: "10.8.0.1/24"}
	if !strings.Contains(writeAmneziaConfig(srv), "ListenPort = 51820") {
		t.Errorf("server config (no endpoint) must have ListenPort:\n%s", writeAmneziaConfig(srv))
	}

	client := amneziaConfigResponse{Address: "10.8.0.2/24", Endpoint: "vpn.example.com:1"}
	if strings.Contains(writeAmneziaConfig(client), "ListenPort") {
		t.Errorf("client config (with endpoint) must not have ListenPort:\n%s", writeAmneziaConfig(client))
	}
}

func TestAmneziaConfigRoundTrip(t *testing.T) {
	first := parseAmneziaConfig(sampleAmneziaConfig)
	second := parseAmneziaConfig(writeAmneziaConfig(first))

	fields := []struct {
		name string
		a, b interface{}
	}{
		{"Address", first.Address, second.Address},
		{"DNS", first.DNS, second.DNS},
		{"MTU", first.MTU, second.MTU},
		{"JC", first.JC, second.JC},
		{"JMIN", first.JMIN, second.JMIN},
		{"JMAX", first.JMAX, second.JMAX},
		{"S1", first.S1, second.S1},
		{"H1", first.H1, second.H1},
		{"I5", first.I5, second.I5},
		{"PublicKey", first.PublicKey, second.PublicKey},
		{"AllowedIPs", first.AllowedIPs, second.AllowedIPs},
		{"Endpoint", first.Endpoint, second.Endpoint},
		{"Keepalive", first.Keepalive, second.Keepalive},
	}
	for _, f := range fields {
		if f.a != f.b {
			t.Errorf("round-trip mismatch for %s: %v != %v", f.name, f.a, f.b)
		}
	}
}
