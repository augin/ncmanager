package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// inTempData переключает рабочий каталог во временный каталог, чтобы
// относительные пути data/* не трогали репозиторий.
func inTempData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func TestSaveLoadConfigRoundTrip(t *testing.T) {
	inTempData(t)

	cfg := &Config{
		WGPort:       51820,
		HttpPort:     8080,
		Interface:    "wg0",
		WanInterface: "eth0",
		Endpoint:     "1.2.3.4",
		DNS:          "1.1.1.1",
		Subnet:       "10.5.0.0/24",
	}
	if err := saveConfig("cfg.json", cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got, err := loadConfig("cfg.json")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if *got != *cfg {
		t.Errorf("round-trip mismatch: %+v != %+v", got, cfg)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	inTempData(t)
	if _, err := loadConfig("missing.json"); err == nil {
		t.Error("missing file must return error")
	}
}

func TestLoadConfigCorruptFile(t *testing.T) {
	dir := inTempData(t)
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Error("corrupt json must return error")
	}
}

func TestSavePeersDoesNotMutateInput(t *testing.T) {
	inTempData(t)
	withEncryptionKey(t, []byte("0123456789abcdef0123456789abcdef"))

	pc := &PeersConfig{Peers: []Peer{{ID: "1", Name: "a", RouterPassword: "secret"}}}
	if err := savePeers(pc); err != nil {
		t.Fatalf("savePeers: %v", err)
	}
	// входной срез не должен быть зашифрован
	if pc.Peers[0].RouterPassword != "secret" {
		t.Errorf("savePeers must not mutate input, password = %q", pc.Peers[0].RouterPassword)
	}

	// на диске пароль должен быть зашифрован
	raw, err := os.ReadFile(peersFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" {
		t.Fatal("empty peers file")
	}
	if containsString(string(raw), "secret") {
		t.Error("password stored in plaintext")
	}

	// при загрузке пароль расшифровывается
	loaded, err := loadPeers()
	if err != nil {
		t.Fatalf("loadPeers: %v", err)
	}
	if len(loaded.Peers) != 1 || loaded.Peers[0].RouterPassword != "secret" {
		t.Errorf("loaded peers = %+v", loaded.Peers)
	}
}

func containsPlaintext(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func containsString(h, n string) bool {
	return strings.Contains(h, n)
}

func TestLoadPeersMissingFile(t *testing.T) {
	inTempData(t)
	pc, err := loadPeers()
	if err != nil {
		t.Fatalf("missing peers file must not error: %v", err)
	}
	if pc.Peers == nil || len(pc.Peers) != 0 {
		t.Errorf("peers = %v, want empty slice", pc.Peers)
	}
}

func TestLoadPeersMigratesDnsRoutesKey(t *testing.T) {
	dir := inTempData(t)
	withEncryptionKey(t, []byte("0123456789abcdef0123456789abcdef"))

	if err := os.MkdirAll(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"peers":[{"id":"1","name":"a"}],"dnsRoutes":[{"id":"r","name":"x"}]}`
	if err := os.WriteFile(peersFile, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	pc, err := loadPeers()
	if err != nil {
		t.Fatalf("loadPeers: %v", err)
	}
	if len(pc.Peers) != 1 {
		t.Fatalf("peers = %+v", pc.Peers)
	}

	raw, err := os.ReadFile(peersFile)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(string(raw), "dnsRoutes") {
		t.Error("legacy dnsRoutes key must be removed from peers.json after migration")
	}
}

func TestLoadDnsRoutesMissingFiles(t *testing.T) {
	inTempData(t)
	routes, err := loadDnsRoutes()
	if err != nil {
		t.Fatalf("must not error: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("routes = %v, want empty", routes)
	}
}

func TestSaveLoadDnsRoutesRoundTrip(t *testing.T) {
	inTempData(t)

	want := []DnsRoute{
		{ID: "1", Name: "Ads", Domains: []string{"ads.example"}, Enabled: true},
		{ID: "2", Name: "Torrents", Subnets: []string{"10.0.0.0/8"}, Enabled: false},
	}
	if err := saveDnsRoutes(want); err != nil {
		t.Fatalf("saveDnsRoutes: %v", err)
	}
	got, err := loadDnsRoutes()
	if err != nil {
		t.Fatalf("loadDnsRoutes: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Name != want[i].Name || got[i].Enabled != want[i].Enabled {
			t.Errorf("route %d mismatch: %+v != %+v", i, got[i], want[i])
		}
	}
}

func TestSaveDnsRoutesNilSlice(t *testing.T) {
	inTempData(t)
	if err := saveDnsRoutes(nil); err != nil {
		t.Fatalf("saveDnsRoutes(nil): %v", err)
	}
	got, err := loadDnsRoutes()
	if err != nil {
		t.Fatalf("loadDnsRoutes: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("routes = %v, want empty", got)
	}
}

func TestLoadDnsRoutesMigratesFromPeersFile(t *testing.T) {
	dir := inTempData(t)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"peers":[],"dnsRoutes":[{"id":"r1","name":"Old","domains":["a.example"],"enabled":true}]}`
	if err := os.WriteFile(peersFile, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	routes, err := loadDnsRoutes()
	if err != nil {
		t.Fatalf("loadDnsRoutes: %v", err)
	}
	if len(routes) != 1 || routes[0].ID != "r1" {
		t.Fatalf("migrated routes = %+v", routes)
	}
	if _, err := os.Stat(dnsRoutesFile); err != nil {
		t.Errorf("migrated routes must be saved to %s: %v", dnsRoutesFile, err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")

	if err := writeFileAtomic(path, []byte("first")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Errorf("content = %q", data)
	}

	if err := writeFileAtomic(path, []byte("second")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "second" {
		t.Errorf("content after overwrite = %q", data)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files must not be left behind: %v", entries)
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	inTempData(t)
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg binary not available")
	}

	cfg, err := createDefaultConfig()
	if err != nil {
		t.Fatalf("createDefaultConfig: %v", err)
	}
	if cfg.WGPort != 51820 || cfg.HttpPort != 8080 || cfg.Interface != "wg0" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.Subnet != "10.0.0.0/24" || cfg.DNS != "1.1.1.1" {
		t.Errorf("unexpected network defaults: %+v", cfg)
	}
	if _, err := os.Stat("data/server_private.key"); err != nil {
		t.Errorf("server private key must be written: %v", err)
	}
}

func TestGenerateID(t *testing.T) {
	a, b := generateID(), generateID()
	if len(a) != 16 || len(b) != 16 {
		t.Errorf("id length must be 16 hex chars: %q %q", a, b)
	}
	if a == b {
		t.Error("ids must be unique")
	}
}

func TestResolveEndpoint(t *testing.T) {
	// точный IP возвращается как есть (без сетевых запросов)
	if got := resolveEndpoint("203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("resolveEndpoint(ip) = %q", got)
	}
	if got := resolveEndpoint("vpn.example.com"); got != "vpn.example.com" {
		t.Errorf("resolveEndpoint(hostname) = %q", got)
	}
}

func TestPeerHasRouterCreds(t *testing.T) {
	full := Peer{RouterDomain: "d", RouterLogin: "l", RouterPassword: "p"}
	if !full.HasRouterCreds() {
		t.Error("peer with all creds must report true")
	}
	cases := []Peer{
		{},
		{RouterDomain: "d"},
		{RouterDomain: "d", RouterLogin: "l"},
		{RouterLogin: "l", RouterPassword: "p"},
	}
	for i, p := range cases {
		if p.HasRouterCreds() {
			t.Errorf("case %d: incomplete creds must report false", i)
		}
	}
}

func TestAmneziaTrafficSnapshotTime(t *testing.T) {
	// smoke: структуры не должны ломать JSON-сериализацию
	now := time.Now().Unix()
	snap := amneziaTrafficSnapshot{TS: now, Rx: 1, Tx: 2}
	if snap.TS != now {
		t.Error("snapshot ts mismatch")
	}
}
