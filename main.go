package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const dataFile = "data/config.json"
const peersFile = "data/peers.json"
const wgConfigFile = "/etc/wireguard/wg0.conf"

type PeersConfig struct {
	Peers     []Peer     `json:"peers"`
	DnsRoutes []DnsRoute `json:"dnsRoutes,omitempty"`
}

type Server struct {
	mu         sync.Mutex
	port       int
	iface      string
	publicKey  string
	endpoint   string
	configPath string
}

type Peer struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	PublicKey      string    `json:"publicKey"`
	PrivateKey     string    `json:"privateKey"`
	CreatedAt      time.Time `json:"createdAt"`
	AllowedIPs     string    `json:"allowedIPs"`
	LastHandshake  time.Time `json:"lastHandshake,omitempty"`
	TransferRx     int64     `json:"transferRx,omitempty"`
	TransferTx     int64     `json:"transferTx,omitempty"`
	Endpoint       string    `json:"endpoint,omitempty"`
	RouterDomain   string    `json:"routerDomain,omitempty"`
	RouterLogin    string    `json:"routerLogin,omitempty"`
	RouterPassword string    `json:"routerPassword,omitempty"`
	Description    string    `json:"description,omitempty"`
	RouterIfName   string    `json:"routerIfName,omitempty"`
}


type Config struct {
	Port         int    `json:"port"`
	Interface    string `json:"interface"`
	WanInterface string `json:"wanInterface"`
	Endpoint     string `json:"endpoint"`
	DNS          string `json:"dns"`
	Subnet       string `json:"subnet"`
	PostUp       string `json:"postUp,omitempty"`
	PostDown     string `json:"postDown,omitempty"`
}

var passwordHash string
var passwordAttempts int
var passwordBlockedUntil time.Time
var authSecret []byte

func main() {
	initAuth()
	initAuthSecret()
	initLogger()

	server := &Server{
		port:       51820,
		iface:      "wg0",
		endpoint:   getPublicIP(),
		configPath: absPath(wgConfigFile),
	}

	cfg, err := loadConfig(dataFile)
	if err != nil {
		log.Printf("No config found, creating default: %v", err)
		cfg, err = createDefaultConfig()
		if err != nil {
			log.Fatalf("failed to create default config: %v", err)
		}
		if err := saveConfig(dataFile, cfg); err != nil {
			log.Fatalf("failed to save default config: %v", err)
		}
	}
	server.endpoint = resolveEndpoint(cfg.Endpoint)

	if cfg.WanInterface == "" {
		cfg.WanInterface = detectDefaultWan()
		_ = saveConfig(dataFile, cfg)
	}

	if cfg.PostUp == "" || cfg.PostDown == "" {
		if data, err := os.ReadFile(wgConfigFile); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "PostUp = ") && cfg.PostUp == "" {
					cfg.PostUp = strings.TrimSpace(strings.TrimPrefix(line, "PostUp = "))
				}
				if strings.HasPrefix(line, "PostDown = ") && cfg.PostDown == "" {
					cfg.PostDown = strings.TrimSpace(strings.TrimPrefix(line, "PostDown = "))
				}
			}
			if cfg.PostUp != "" || cfg.PostDown != "" {
				_ = saveConfig(dataFile, cfg)
			}
		}
	}

	peersCfg, err := loadPeers()
	if err != nil {
		log.Printf("No peers config found, using empty: %v", err)
		peersCfg = &PeersConfig{Peers: []Peer{}}
	}

	if err := generateWgConfig(cfg, peersCfg.Peers); err != nil {
		log.Printf("Warning: could not generate wg config on startup: %v", err)
	}

	syncServerKeyFromRunning()

	if _, statErr := os.Stat(wgConfigFile); statErr == nil {
		if _, showErr := exec.Command("wg", "show", "wg0").CombinedOutput(); showErr != nil {
			out, upErr := exec.Command("wg-quick", "up", wgConfigFile).CombinedOutput()
			if upErr != nil {
				log.Printf("wg-quick up failed: %s", strings.TrimSpace(string(out)))
			} else {
				log.Printf("wg0 started on startup")
			}
		} else {
			log.Printf("wg0 already running, config regenerated but interface kept")
		}
	}

	http.HandleFunc("/", serveIndex)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	api := http.NewServeMux()
	api.HandleFunc("/status", withAuth(server.getStatus))
	api.HandleFunc("/config", withAuth(server.getConfig))
	api.HandleFunc("/config/save", withAuth(server.saveConfig))
	api.HandleFunc("/interfaces", withAuth(server.listInterfaces))
	api.HandleFunc("/peers", withAuth(server.listPeers))
	api.HandleFunc("/peers/add", withAuth(server.addPeer))
	api.HandleFunc("/peers/remove", withAuth(server.removePeer))
	api.HandleFunc("/peers/update", withAuth(server.updatePeer))
	api.HandleFunc("/peers/qrcode/", withAuth(server.getPeerQR))
	api.HandleFunc("/peers/config/", withAuth(server.getPeerConfigText))
	api.HandleFunc("/peers/download/", withAuth(server.downloadPeerConfig))
	api.HandleFunc("/peers/keenetic/", withAuth(server.importPeerToKeenetic))
	api.HandleFunc("/peers/keenetic-dl/", withAuth(server.downloadPeerKeeneticConfig))
	api.HandleFunc("/peers/keenetic-dns/", withAuth(server.configurePeerDns))
	api.HandleFunc("/peers/keenetic-dns-routes/", withAuth(server.configurePeerDnsRoutes))
	api.HandleFunc("/peers/keenetic-components/", withAuth(server.configurePeerComponents))
	api.HandleFunc("/components/apply", withAuth(server.configurePeerComponents))
	api.HandleFunc("/components/apply/status", withAuth(server.getComponentsApplyStatus))
	api.HandleFunc("/dns/routes", withAuth(server.listDnsRoutes))
	api.HandleFunc("/dns/routes/create", withAuth(server.createDnsRoute))
	api.HandleFunc("/dns/routes/update", withAuth(server.updateDnsRoute))
	api.HandleFunc("/dns/routes/delete", withAuth(server.deleteDnsRoute))
	api.HandleFunc("/dns/routes/apply", withAuth(server.applyDnsRoutesToRouter))
	api.HandleFunc("/dns/apply/status", withAuth(server.getDnsApplyStatus))
	api.HandleFunc("/presets/dns-routes", withAuth(server.getDnsRoutePresets))
	api.HandleFunc("/server/start", withAuth(server.startServer))
	api.HandleFunc("/server/stop", withAuth(server.stopServer))
	api.HandleFunc("/server/restart", withAuth(server.restartServer))
	api.HandleFunc("/keys/generate", withAuth(generateKeys))
	api.HandleFunc("/login", loginHandler)
	api.HandleFunc("/logout", withAuth(logoutHandler))
	api.HandleFunc("/logs", withAuth(server.getLogs))
	api.HandleFunc("/router/dump/", withAuth(server.dumpRouterRCI))
	api.HandleFunc("/amnezia/status", withAuth(server.getAmneziaStatus))
	api.HandleFunc("/amnezia/install", withAuth(server.installAmnezia))
	api.HandleFunc("/amnezia/import", withAuth(server.importAmneziaConfig))
	api.HandleFunc("/amnezia/interfaces", withAuth(server.getAmneziaInterfaces))
	api.HandleFunc("/amnezia/interface/", withAuth(server.manageAmneziaInterface))
	http.Handle("/api/", http.StripPrefix("/api", api))

	log.Printf("WireGuard Manager starting on :8080")
	log.Printf("Endpoint: %s", server.endpoint)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initLogger() {
	os.MkdirAll("data", 0700)
	f, err := os.OpenFile("data/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log file: %v", err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
}

func initAuth() {
	if b, err := os.ReadFile("data/.auth"); err == nil {
		passwordHash = strings.TrimSpace(string(b))
		log.Printf("AUTH INIT: loaded hash from file, len=%d hash_prefix=%s", len(passwordHash), passwordHash[:min(8, len(passwordHash))])
	} else if p, ok := os.LookupEnv("WG_MANAGER_PASSWORD"); ok {
		passwordHash = sha256String(p)
		_ = os.MkdirAll("data", 0700)
		_ = os.WriteFile("data/.auth", []byte(sha256String(p)), 0600)
		log.Printf("AUTH INIT: using env password hash len=%d", len(passwordHash))
	} else {
		passwordHash = sha256String("admin")
		_ = os.MkdirAll("data", 0700)
		_ = os.WriteFile("data/.auth", []byte(sha256String("admin")), 0600)
		log.Printf("AUTH INIT: using default admin hash len=%d hash_prefix=%s", len(passwordHash), passwordHash[:min(8, len(passwordHash))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func getCIDRPrefix(ipnet *net.IPNet) int {
	ones, _ := ipnet.Mask.Size()
	return ones
}

func initAuthSecret() {
	path := "data/.secret"
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		authSecret = b
		return
	}
	authSecret = make([]byte, 32)
	if _, err := rand.Read(authSecret); err != nil {
		log.Fatalf("failed to generate auth secret: %v", err)
	}
	_ = os.MkdirAll("data", 0700)
	_ = os.WriteFile(path, authSecret, 0600)
}

func generateToken(user string, passwordHash string, ttl time.Duration) string {
	expiry := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s|%s|%d", user, passwordHash, expiry)
	sig := hmac.New(sha256.New, authSecret)
	sig.Write([]byte(payload))
	return base64.URLEncoding.EncodeToString([]byte(payload)) + "." + base64.URLEncoding.EncodeToString(sig.Sum(nil))
}

func validateToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		log.Printf("TOKEN VALIDATE: bad format, parts=%d", len(parts))
		return false
	}
	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Printf("TOKEN VALIDATE: bad payload base64")
		return false
	}
	expectedSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("TOKEN VALIDATE: bad sig base64")
		return false
	}
	payload := string(payloadBytes)
	sig := hmac.New(sha256.New, authSecret)
	sig.Write([]byte(payload))
	if !hmac.Equal(sig.Sum(nil), expectedSig) {
		log.Printf("TOKEN VALIDATE: bad signature")
		return false
	}
	segments := strings.Split(payload, "|")
	if len(segments) != 3 {
		log.Printf("TOKEN VALIDATE: bad segments=%d", len(segments))
		return false
	}
	if segments[1] != passwordHash {
		log.Printf("TOKEN VALIDATE: password hash mismatch")
		return false
	}
	expiry, _ := strconv.ParseInt(segments[2], 10, 64)
	if time.Now().After(time.Unix(expiry, 0)) {
		log.Printf("TOKEN VALIDATE: expired at %v", time.Unix(expiry, 0))
		return false
	}
	log.Printf("TOKEN VALIDATE: OK prefix=%s", token[:8])
	return true
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "templates/index.html")
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func createDefaultConfig() (*Config, error) {
	priv, _, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key pair: %w", err)
	}
	cfg := &Config{
		Port:      51820,
		Interface: "wg0",
		Endpoint:  getPublicIP(),
		DNS:       "1.1.1.1",
		Subnet:    "10.0.0.0/24",
	}
	if err := savePrivateKey("data/server_private.key", priv); err != nil {
		return nil, fmt.Errorf("failed to save server private key: %w", err)
	}
	return cfg, nil
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(cfg)
}

func loadPeers() (*PeersConfig, error) {
	f, err := os.Open(peersFile)
	if err != nil {
		return &PeersConfig{Peers: []Peer{}}, nil
	}
	defer f.Close()
	var pc PeersConfig
	if err := json.NewDecoder(f).Decode(&pc); err != nil {
		return &PeersConfig{Peers: []Peer{}}, nil
	}
	if pc.Peers == nil {
		pc.Peers = []Peer{}
	}
	return &pc, nil
}

func savePeers(pc *PeersConfig) error {
	if err := os.MkdirAll(filepath.Dir(peersFile), 0755); err != nil {
		return err
	}
	f, err := os.Create(peersFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(pc)
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func resolveEndpoint(endpoint string) string {
	if endpoint == "" || endpoint == "AUTO" {
		return getPublicIP()
	}
	if net.ParseIP(endpoint) != nil {
		return endpoint
	}
	return endpoint
}

func detectDefaultWan() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.To4() != nil {
				return iface.Name
			}
		}
	}
	return "eth0"
}

func (s *Server) listInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	if len(result) == 0 {
		result = []string{"eth0"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig(dataFile)
	if err != nil {
		http.Error(w, "failed to load config", http.StatusInternalServerError)
		return
	}
	peersCfg, _ := loadPeers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"port":         cfg.Port,
		"interface":    cfg.Interface,
		"wanInterface": cfg.WanInterface,
		"endpoint":     cfg.Endpoint,
		"dns":          cfg.DNS,
		"subnet":       cfg.Subnet,
		"postUp":       cfg.PostUp,
		"postDown":     cfg.PostDown,
		"peers":        peersCfg.Peers,
		"dnsRoutes":    peersCfg.DnsRoutes,
	})
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	oldCfg, _ := loadConfig(dataFile)

	s.mu.Lock()
	cfg := oldCfg
	if cfg == nil {
		cfg = &Config{}
	}
	if v, ok := req["port"].(float64); ok {
		cfg.Port = int(v)
	}
	if v, ok := req["interface"].(string); ok {
		cfg.Interface = v
	}
	if v, ok := req["wanInterface"].(string); ok && v != "" {
		cfg.WanInterface = v
	}
	if v, ok := req["dns"].(string); ok {
		cfg.DNS = v
	}
	if v, ok := req["subnet"].(string); ok {
		cfg.Subnet = v
	}
	if v, ok := req["postUp"].(string); ok {
		cfg.PostUp = v
	}
	if v, ok := req["postDown"].(string); ok {
		cfg.PostDown = v
	}
	if v, ok := req["endpoint"].(string); ok {
		cfg.Endpoint = resolveEndpoint(v)
	}

	if err := saveConfig(dataFile, cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.port = cfg.Port
	s.iface = cfg.Interface
	s.endpoint = cfg.Endpoint
	s.mu.Unlock()

	peersCfg, _ := loadPeers()
	if peers, ok := req["peers"].([]any); ok {
		peersCfg.Peers = nil
		for _, p := range peers {
			pb, _ := json.Marshal(p)
			var peer Peer
			if err := json.Unmarshal(pb, &peer); err == nil {
				peersCfg.Peers = append(peersCfg.Peers, peer)
			}
		}
	}
	_ = savePeers(peersCfg)

	if err := generateWgConfig(cfg, peersCfg.Peers); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate wg config: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.restartServerDirect(); err != nil {
		http.Error(w, fmt.Sprintf("failed to restart server: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) listPeers(w http.ResponseWriter, r *http.Request) {
	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, _ := loadConfig(dataFile)
	_ = syncPeersWithWireGuard(cfg, peersCfg.Peers)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peersCfg.Peers)
}

func (s *Server) addPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "Peer-" + time.Now().Format("20060102-150405")
	}

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, _ := loadConfig(dataFile)
	allowedIP, err := nextAvailableIP(peersCfg.Peers, cfg.Subnet)
	if err != nil {
		http.Error(w, "no available IPs in subnet", http.StatusConflict)
		return
	}

	priv, pub, err := generateKeyPair()
	if err != nil {
		http.Error(w, "failed to generate key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	peer := Peer{
		ID:         generateID(),
		Name:       req.Name,
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
		AllowedIPs: allowedIP,
	}
	peersCfg.Peers = append(peersCfg.Peers, peer)

	if err := savePeers(peersCfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = addPeerWireGuard(peer)
	_ = generateWgConfig(cfg, peersCfg.Peers)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(peer)
}

func (s *Server) removePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var peerToRemove *Peer
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == req.ID {
			peerToRemove = &peersCfg.Peers[i]
			break
		}
	}
	if peerToRemove == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	filtered := peersCfg.Peers[:0]
	for _, p := range peersCfg.Peers {
		if p.ID != req.ID {
			filtered = append(filtered, p)
		}
	}
	peersCfg.Peers = filtered

	_ = savePeers(peersCfg)
	if err := removePeerWireGuard(peerToRemove.PublicKey); err != nil {
		log.Printf("removePeer wg set failed: %v", err)
	}
	cfg, _ := loadConfig(dataFile)
	_ = generateWgConfig(cfg, peersCfg.Peers)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string `json:"id"`
		RouterDomain   string `json:"routerDomain"`
		RouterLogin    string `json:"routerLogin"`
		RouterPassword string `json:"routerPassword"`
		Description    string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == req.ID {
			peersCfg.Peers[i].RouterDomain = req.RouterDomain
			peersCfg.Peers[i].RouterLogin = req.RouterLogin
			if req.RouterPassword != "" {
				peersCfg.Peers[i].RouterPassword = req.RouterPassword
			}
			peersCfg.Peers[i].Description = req.Description
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	_ = savePeers(peersCfg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) getPeerQR(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	log.Printf("QR: path=%s query_id=%s", r.URL.Path, id)
	peersCfg, _ := loadPeers()
	globalCfg, _ := loadConfig(dataFile)
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == id {
			peer := &peersCfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, globalCfg.DNS)
			qr, err := qrcode.Encode(peerConf, qrcode.Medium, 256)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Write(qr)
			return
		}
	}
	log.Printf("QR peer not found id=%s total=%d", id, len(peersCfg.Peers))
	http.Error(w, "peer not found", http.StatusNotFound)
}

func (s *Server) getPeerConfigText(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	log.Printf("ConfigText: path=%s rawQuery=%s id=%s", r.URL.Path, r.URL.RawQuery, id)
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	peersCfg, _ := loadPeers()
	globalCfg, _ := loadConfig(dataFile)
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == id {
			peer := &peersCfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, globalCfg.DNS)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(peerConf))
			return
		}
	}
	log.Printf("ConfigText peer not found id=%s", id)
	http.Error(w, "peer not found", http.StatusNotFound)
}

func (s *Server) downloadPeerConfig(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	log.Printf("Download request id=%s", id)
	peersCfg, _ := loadPeers()
	globalCfg, _ := loadConfig(dataFile)
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == id {
			peer := &peersCfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, globalCfg.DNS)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", sanitizeFilename(peer.Name)))
			w.Write([]byte(peerConf))
			return
		}
	}
	log.Printf("Download peer not found id=%s", id)
	http.Error(w, "peer not found", http.StatusNotFound)
}

func sanitizeFilename(s string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
	return re.ReplaceAllString(s, "_")
}

func generateKeeneticServerConfig(peer *Peer, serverPub, iface, endpoint string, port int, subnet, wanIface string) string {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil || ipnet == nil {
		ipnet = &net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(24, 32)}
	}
	serverIP := ipnet.IP.To4()
	serverIP[3]++
	serverAddr := fmt.Sprintf("%s/%d", serverIP.String(), getCIDRPrefix(ipnet))
	if wanIface == "" {
		wanIface = "eth0"
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", strings.TrimSpace(serverPub)))
	b.WriteString(fmt.Sprintf("PostUp = iptables -A INPUT -p udp --dport %d -j ACCEPT || true; iptables -A FORWARD -i %s -o %%i -j ACCEPT || true; iptables -A FORWARD -i %%i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE || true; ip route add default dev %s table 110 || true; ip rule add iif %%i table 110 || true;\n", port, wanIface, wanIface, wanIface))
	b.WriteString(fmt.Sprintf("PostDown = iptables -D INPUT -p udp --dport %d -j ACCEPT || true; iptables -D FORWARD -i %s -o %%i -j ACCEPT || true; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE || true; ip route del default dev %s table 110 || true; ip rule del iif %%i table 110 || true;\n", port,wanIface,wanIface,wanIface))
	b.WriteString(fmt.Sprintf("SaveConfig = true\n"))

	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("# %s\n", peer.Name))
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", peer.AllowedIPs))
	b.WriteString("PersistentKeepalive = 25\n")

	return b.String()
}

func (s *Server) importPeerToKeenetic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	id := parts[3]

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	globalCfg, _ := loadConfig(dataFile)
	peerIdx := -1
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == id {
			peerIdx = i
			break
		}
	}
	if peerIdx < 0 {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := &peersCfg.Peers[peerIdx]

	serverPub := getActualServerPublicKey()
	if serverPub == "" {
		serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
		serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
	}
	confContent := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, globalCfg.DNS)

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	result, err := importWireGuardConfigToRouter(
		peer.RouterDomain,
		peer.RouterLogin,
		peer.RouterPassword,
		[]byte(confContent),
		sanitizeFilename(peer.Name)+".conf",
		peer.AllowedIPs,
		"0.0.0.0/0",
		s.endpoint,
		s.port,
	)
	if err != nil {
		log.Printf("keenetic import failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router import failed: %v", err), http.StatusBadGateway)
		return
	}

	ifName := result.Created
	if ifName == "" {
		ifName = result.Intersects
	}
	if ifName != "" && ifName != peer.RouterIfName {
		peersCfg.Peers[peerIdx].RouterIfName = ifName
		_ = savePeers(peersCfg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"created":    result.Created,
		"intersects": result.Intersects,
		"messages":   result.Messages,
		"peer":       peer.Name,
	})
}

func (s *Server) downloadPeerKeeneticConfig(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	id := parts[3]
	peersCfg, _ := loadPeers()
	globalCfg, _ := loadConfig(dataFile)
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == id {
			peer := &peersCfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, globalCfg.DNS)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", sanitizeFilename(peer.Name)))
			w.Write([]byte(peerConf))
			return
		}
	}
	http.Error(w, "peer not found", http.StatusNotFound)
}

func (s *Server) configurePeerComponents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerID := ""

	var req struct {
		PeerID string `json:"peerId"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			peerID = req.PeerID
		}
	}

	if peerID == "" {
		parts := strings.Split(r.URL.Path, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] != "" {
				peerID = parts[i]
				break
			}
		}
	}

	if peerID == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}

	peersCfg, _ := loadPeers()
	peerIdx := -1
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == peerID {
			peerIdx = i
			break
		}
	}
	if peerIdx < 0 {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := peersCfg.Peers[peerIdx]

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	globalCfg, _ := loadConfig(dataFile)

	os.WriteFile("/tmp/components-apply.status", []byte("running"), 0644)
	os.WriteFile("/tmp/components-apply.log", []byte("Запуск настройки компонентов...\n"), 0644)

	go func() {
		httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
		if err != nil {
			componentsAppendLog(fmt.Sprintf("❌ Ошибка подключения к %s: %v\n", peer.RouterDomain, err))
			os.WriteFile("/tmp/components-apply.status", []byte("failed"), 0644)
			return
		}

		serverPub := getActualServerPublicKey()
		if serverPub == "" {
			serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
			serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
		}

		res := configureRouterComponents(httpClient, baseURL, &peer, serverPub, s.endpoint, s.port, globalCfg.WanInterface)

		var status string
		if res.Status == "error" {
			status = "failed"
		} else {
			status = "completed"
		}
		os.WriteFile("/tmp/components-apply.status", []byte(status), 0644)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) getComponentsApplyStatus(w http.ResponseWriter, r *http.Request) {
	status := "idle"
	stBytes, _ := os.ReadFile("/tmp/components-apply.status")
	status = strings.TrimSpace(string(stBytes))

	logBytes, _ := os.ReadFile("/tmp/components-apply.log")
	logText := string(logBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"log":    logText,
	})
}

func generateKeys(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := generateKeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"privateKey": priv,
		"publicKey":  pub,
	})
}

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("data/app.log")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(strings.Join(lines, "\n")))
}

func (s *Server) dumpRouterRCI(w http.ResponseWriter, r *http.Request) {
	peersCfg, _ := loadPeers()
	if len(peersCfg.Peers) == 0 {
		http.Error(w, "no peers configured", http.StatusBadRequest)
		return
	}
	peer := &peersCfg.Peers[0]
	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured", http.StatusBadRequest)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	ifaceQuery := ""
	if len(parts) > 3 && parts[3] != "" {
		ifaceQuery = parts[3]
	}
	httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
	if err != nil {
		http.Error(w, "router auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if ifaceQuery != "" {
		postPayload := map[string]any{ifaceQuery: nil}
		if data, _, err := keeneticRciPost(httpClient, baseURL, postPayload); err == nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write(data)
		} else {
			http.Error(w, "rci query failed: "+err.Error(), http.StatusBadGateway)
		}
		return
	}
	resp, err := httpClient.Get(baseURL + "/rci/")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data)
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	up, info, _ := checkWireGuardStatus(s.iface)
	status := map[string]interface{}{
		"running": up,
	}
	if info != nil {
		status["publicKey"] = info.PublicKey
		status["listenPort"] = info.ListenPort
		status["peers"] = info.Peers
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) startServer(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("wg-quick", "up", s.configPath).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "already exists") || strings.Contains(msg, "is already up") {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "already running"})
			return
		}
		log.Printf("start error: %s", msg)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  msg,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) stopServer(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	path := s.configPath
	s.mu.Unlock()
	out, _ := exec.Command("wg-quick", "down", path).CombinedOutput()
	if len(out) > 0 {
		log.Printf("stop: %s", string(out))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) restartServer(w http.ResponseWriter, r *http.Request) {
	if err := s.restartServerDirect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) restartServerDirect() error {
	s.mu.Lock()
	path := s.configPath
	s.mu.Unlock()
	downOut, downErr := exec.Command("wg-quick", "down", path).CombinedOutput()
	if downErr != nil {
		log.Printf("wg-quick down: %s", string(downOut))
	}
	time.Sleep(500 * time.Millisecond)
	out, err := exec.Command("wg-quick", "up", path).CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "already exists") || strings.Contains(msg, "is already up") {
			return nil
		}
		log.Printf("wg-quick up failed: %s", msg)
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

func generateKeyPair() (priv, pub string, err error) {
	cmd := exec.Command("wg", "genkey")
	privBuf := new(bytes.Buffer)
	cmd.Stdout = privBuf
	if err = cmd.Run(); err != nil {
		return "", "", fmt.Errorf("wg genkey failed: %w", err)
	}
	priv = strings.TrimSpace(privBuf.String())

	cmd2 := exec.Command("wg", "pubkey")
	cmd2.Stdin = strings.NewReader(priv)
	pubBuf := new(bytes.Buffer)
	cmd2.Stdout = pubBuf
	if err = cmd2.Run(); err != nil {
		return "", "", fmt.Errorf("wg pubkey failed: %w", err)
	}
	pub = strings.TrimSpace(pubBuf.String())
	return
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func nextAvailableIP(peers []Peer, subnet string) (string, error) {
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	base := ipnet.IP
	maskSize, _ := ipnet.Mask.Size()

	used := make(map[string]bool)
	networkAddr := base.String()
	used[networkAddr] = true
	serverIP := make(net.IP, len(base))
	copy(serverIP, base)
	serverIP[3]++
	used[serverIP.String()] = true

	for _, p := range peers {
		parts := strings.Split(p.AllowedIPs, "/")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			used[ip] = true
		}
	}

	for i := 1; i < (1<<(32-maskSize))-1; i++ {
		ip := make(net.IP, len(base))
		copy(ip, base)
		v := i
		for j := 3; j >= 0; j-- {
			if v > 0 {
				octet := int(base[j]) + (v & 0xFF)
				ip[j] = byte(octet)
				v >>= 8
			}
		}
		candidate := ip.String()
		if !used[candidate] {
			return candidate + "/32", nil
		}
	}
	return "", fmt.Errorf("no available IP in subnet %s", subnet)
}

type wgInfo struct {
	PublicKey  string
	ListenPort int
	Peers      []wgPeer
}

type wgPeer struct {
	PublicKey     string
	AllowedIPs    string
	LastHandshake time.Time
	TransferRx    int64
	TransferTx    int64
	Endpoint      string
}

func checkWireGuardStatus(iface string) (bool, *wgInfo, error) {
	cmd := exec.Command("wg", "show", iface, "public-key")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil, err
	}
	pubKey := strings.TrimSpace(string(out))

	cmd = exec.Command("wg", "show", iface, "dump")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return false, nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return false, nil, fmt.Errorf("empty output")
	}
	lines := strings.Split(raw, "\n")
	log.Printf("WG DUMP: total_lines=%d first=%q", len(lines), lines[0])
	info := &wgInfo{PublicKey: pubKey}
	interfaceParsed := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if !interfaceParsed && isBase64(parts[0]) && len(parts) >= 3 {
			// interface header: privkey pubkey port
			if len(parts) > 2 {
				fmt.Sscanf(parts[2], "%d", &info.ListenPort)
			}
			interfaceParsed = true
			log.Printf("WG IFACE: pubkey=%s port=%d", info.PublicKey[:12], info.ListenPort)
			continue
		}
		if isBase64(parts[0]) && len(parts) >= 7 {
			// Peer line: pubkey	preshared	endpoint	allowedips	handshake_ts	rx	tx...
			p := wgPeer{PublicKey: parts[0]}
			if len(parts) > 2 {
				p.Endpoint = parts[2]
			}
			if len(parts) > 3 {
				p.AllowedIPs = parts[3]
			}
			if len(parts) > 4 && parts[4] != "0" && parts[4] != "(none)" {
				ts, _ := strconv.ParseInt(parts[4], 10, 64)
				if ts > 0 {
					p.LastHandshake = time.Unix(ts, 0)
				}
			}
			if len(parts) > 5 {
				fmt.Sscanf(parts[5], "%d", &p.TransferRx)
			}
			if len(parts) > 6 {
				fmt.Sscanf(parts[6], "%d", &p.TransferTx)
			}
			log.Printf("WG PEER: pubkey=%s endpoint=%s allowed=%s hs=%v rx=%d tx=%d",
				truncate(p.PublicKey, 12), p.Endpoint, p.AllowedIPs, p.LastHandshake, p.TransferRx, p.TransferTx)
			info.Peers = append(info.Peers, p)
		} else if parts[0] == "peer" {
			// Newer format with "peer" keyword
			p := wgPeer{PublicKey: parts[1]}
			if len(parts) > 3 {
				p.LastHandshake, _ = time.Parse("2006-01-02 15:04:05", parts[2]+" "+parts[3])
			}
			if len(parts) > 4 {
				fmt.Sscanf(parts[4], "%d", &p.TransferRx)
			}
			if len(parts) > 5 {
				fmt.Sscanf(parts[5], "%d", &p.TransferTx)
			}
			if len(parts) > 6 {
				p.AllowedIPs = parts[6]
			}
			if len(parts) > 7 {
				p.Endpoint = parts[7]
			}
			info.Peers = append(info.Peers, p)
		}
	}
	return true, info, nil
}

func isBase64(s string) bool {
	if s == "" || len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func addPeerWireGuard(p Peer) error {
	cmd := exec.Command("wg", "set", "wg0", "peer", p.PublicKey, "allowed-ips", p.AllowedIPs)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

func removePeerWireGuard(pubKey string) error {
	cmd := exec.Command("wg", "set", "wg0", "peer", pubKey, "remove")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

func syncPeersWithWireGuard(cfg *Config, peers []Peer) error {
	if cfg == nil {
		return nil
	}
	_, info, err := checkWireGuardStatus("wg0")
	if err != nil {
		return err
	}
	peerMap := make(map[string]wgPeer)
	for _, p := range info.Peers {
		peerMap[p.PublicKey] = p
	}
	for i := range peers {
		if p, ok := peerMap[peers[i].PublicKey]; ok {
			peers[i].LastHandshake = p.LastHandshake
			peers[i].TransferRx = p.TransferRx
			peers[i].TransferTx = p.TransferTx
			peers[i].Endpoint = p.Endpoint
		}
	}
	return nil
}

func generateWgConfig(cfg *Config, peers []Peer) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	serverPrivBytes, err := loadPrivateKey("data/server_private.key")
	if err != nil || len(serverPrivBytes) == 0 {
		priv, _, genErr := generateKeyPair()
		if genErr != nil {
			return fmt.Errorf("failed to generate server key: %w", genErr)
		}
		if err := savePrivateKey("data/server_private.key", priv); err != nil {
			return fmt.Errorf("failed to save server key: %w", err)
		}
		serverPrivBytes = []byte(priv)
	}
	serverPriv := strings.TrimSpace(string(serverPrivBytes))

	subnet := cfg.Subnet
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	serverIP := ipnet.IP
	serverIP = net.IP{serverIP[0], serverIP[1], serverIP[2], serverIP[3] + 1}
	serverAddr := fmt.Sprintf("%s/%d", serverIP.String(), getCIDRPrefix(ipnet))

	wanIface := cfg.WanInterface
	if wanIface == "" {
		wanIface = "eth0"
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.Port))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPriv))
	if cfg.PostUp != "" {
		b.WriteString(fmt.Sprintf("PostUp = %s\n", cfg.PostUp))
	} else {
		b.WriteString(fmt.Sprintf("PostUp = iptables -A INPUT -p udp --dport %d -j ACCEPT || true; iptables -A FORWARD -i %s -o %%i -j ACCEPT || true; iptables -A FORWARD -i %%i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE || true; ip route add default dev %s table 110 || true; ip rule add iif %%i table 110 || true;\n", cfg.Port, wanIface, wanIface, wanIface))
	}
	if cfg.PostDown != "" {
		b.WriteString(fmt.Sprintf("PostDown = %s\n", cfg.PostDown))
	} else {
		b.WriteString(fmt.Sprintf("PostDown = iptables -D INPUT -p udp --dport %d -j ACCEPT || true; iptables -D FORWARD -i %s -o %%i -j ACCEPT || true; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE || true; ip route del default dev %s table 110 || true; ip rule del iif %%i table 110 || true;\n", cfg.Port,wanIface,wanIface,wanIface))
	}
	b.WriteString("SaveConfig = true\n")

	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("# %s\n", p.Name))
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey))
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", p.AllowedIPs))
	}
	return os.WriteFile(wgConfigFile, []byte(b.String()), 0600)
}

func generatePeerConfig(peer *Peer, serverPub, iface, endpoint string, port int, dns string) string {
	peerPriv := peer.PrivateKey
	if peerPriv == "" {
		peerPriv, _, _ = generateKeyPair()
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", peerPriv))
	b.WriteString(fmt.Sprintf("Address = %s\n", peer.AllowedIPs))
	if dns != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", dns))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", strings.TrimSpace(string(serverPub))))
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", endpoint, port))
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

func savePrivateKey(path, key string) error {
	return os.WriteFile(path, []byte(key), 0600)
}

func loadPrivateKey(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func getPublicKeyFromPrivate(privKeyBytes []byte) (string, error) {
	trimmed := strings.TrimSpace(string(privKeyBytes))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewReader([]byte(trimmed))
	pubBuf := new(bytes.Buffer)
	cmd.Stdout = pubBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg pubkey failed: %w", err)
	}
	return strings.TrimSpace(pubBuf.String()), nil
}

func sha256String(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func checkPassword(pw string) bool {
	if time.Now().Before(passwordBlockedUntil) {
		return false
	}
	if sha256String(pw) == passwordHash {
		passwordAttempts = 0
		return true
	}
	passwordAttempts++
	if passwordAttempts >= 5 {
		passwordBlockedUntil = time.Now().Add(5 * time.Minute)
	}
	return false
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token == "" {
		token = r.Header.Get("X-Session-Token")
	}
	if token != "" && validateToken(token) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	return false
}

func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		handler(w, r)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	log.Printf("LOGIN ATTEMPT: password=%s", req.Password)
	if checkPassword(req.Password) {
		token := generateToken("admin", passwordHash, 168*time.Hour)
		log.Printf("LOGIN SUCCESS: token prefix=%s", token[:8])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"token":  token,
		})
	} else {
		log.Printf("LOGIN FAILED")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid password"})
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) getAmneziaStatus(w http.ResponseWriter, r *http.Request) {
	_, err := exec.LookPath("awg")
	installed := err == nil
	version := ""
	if installed {
		out, _ := exec.Command("awg", "-v").CombinedOutput()
		v := strings.TrimSpace(string(out))
		if v != "" {
			version = v
			installed = true
		} else {
			installed = false
		}
	}

	status := "idle"
	logBytes, _ := os.ReadFile("/tmp/amnezia-install.log")
	logText := string(logBytes)

	stBytes, _ := os.ReadFile("/tmp/amnezia-install.status")
	status = strings.TrimSpace(string(stBytes))
	if status == "" && installed {
		status = "completed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"installed":      installed,
		"installStatus":  status,
		"installLogTail": logText,
		"version":        version,
	})
}

func (s *Server) installAmnezia(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	os.WriteFile("/tmp/amnezia-install.status", []byte("running"), 0644)
	os.WriteFile("/tmp/amnezia-install.log", []byte(""), 0644)
	go func() {
		script := `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "Updating apt..."
apt-get update -q 2>&1 || true
apt-get upgrade -y -q \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" 2>&1 || true

echo "Installing dependencies..."
apt-get install -y -q \
  python3 net-tools curl ufw iptables qrencode bc ca-certificates gnupg \
  build-essential git libmnl-dev pkg-config dkms 2>&1 || true

echo "Installing kernel headers..."
running_kernel="$(uname -r)"
if [[ ! -d "/lib/modules/${running_kernel}/build" ]]; then
  apt-get install -y -q "linux-headers-${running_kernel}" 2>&1 || true
fi
if [[ ! -d "/lib/modules/${running_kernel}/build" ]]; then
  apt-get install -y -q linux-headers-amd64 2>/dev/null || \
  apt-get install -y -q linux-headers-generic 2>/dev/null || true
fi

echo "Building amneziawg kernel module..."
tmp_mod="/tmp/amneziawg-linux-kernel-module"
rm -rf "$tmp_mod"
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$tmp_mod" 2>&1 || {
  echo "Failed to clone kernel module"; exit 1
}
(
  cd "$tmp_mod/src" || exit 1
  make dkms-install 2>&1 || exit 1
  mod_ver=$(grep -oP 'version\s*"\K[^"]+' dkms.conf 2>/dev/null || echo "1.0.0")
  dkms add -m amneziawg -v "$mod_ver" 2>/dev/null || true
  dkms build -m amneziawg -v "$mod_ver" 2>&1 || exit 1
  dkms install -m amneziawg -v "$mod_ver" 2>&1 || exit 1
) || {
  echo "Failed to build kernel module"; exit 1
}
rm -rf "$tmp_mod"

echo "Building amneziawg-tools..."
tmp_tools="/tmp/amneziawg-tools"
rm -rf "$tmp_tools"
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git "$tmp_tools" 2>&1 || {
  echo "Failed to clone tools"; exit 1
}
(
  cd "$tmp_tools/src" || exit 1
  make 2>&1 && make install 2>&1
) || {
  echo "Failed to build tools"; exit 1
}
rm -rf "$tmp_tools"

echo "Loading module..."
modprobe amneziawg 2>/dev/null || true

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 -q 2>&1 || true
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || \
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "Done"
`
		cmd := exec.Command("bash", "-c", script+" 2>&1")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("amnezia install: stdout pipe error: %v", err)
			os.WriteFile("/tmp/amnezia-install.status", []byte("failed"), 0644)
			return
		}
		if err := cmd.Start(); err != nil {
			log.Printf("amnezia install: start error: %v", err)
			os.WriteFile("/tmp/amnezia-install.status", []byte("failed"), 0644)
			return
		}
		var logBuf bytes.Buffer
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text() + "\n"
			logBuf.WriteString(line)
			os.WriteFile("/tmp/amnezia-install.log", []byte(logBuf.String()), 0644)
		}
		if err := cmd.Wait(); err != nil {
			logBuf.WriteString("\n[ERROR] " + err.Error() + "\n")
			os.WriteFile("/tmp/amnezia-install.log", []byte(logBuf.String()), 0644)
			os.WriteFile("/tmp/amnezia-install.status", []byte("failed"), 0644)
		} else {
			os.WriteFile("/tmp/amnezia-install.status", []byte("completed"), 0644)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) importAmneziaConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ConfigText string `json:"configText"`
		Name       string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ConfigText == "" {
		http.Error(w, "config text required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)

	configText := req.ConfigText
	configText = strings.Replace(configText, "[Interface]", "[Interface]\nTable = off", 1)
	var lines []string
	for _, line := range strings.Split(configText, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "DNS = ") {
			lines = append(lines, line)
		}
	}
	configText = strings.Join(lines, "\n")
	if !strings.Contains(configText, "PersistentKeepalive = ") {
		configText = strings.Replace(configText, "[Peer]", "[Peer]\nPersistentKeepalive = 27", 1)
	}

	os.MkdirAll("/etc/amnezia/amneziawg", 0700)
	confPath := fmt.Sprintf("/etc/amnezia/amneziawg/%s.conf", name)
	if err := os.WriteFile(confPath, []byte(configText), 0600); err != nil {
		http.Error(w, "failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	exec.Command("modprobe", "amneziawg").CombinedOutput()

	out, upErr := exec.Command("awg-quick", "up", name).CombinedOutput()
	if upErr != nil {
		os.Remove(confPath)
		http.Error(w, "awg-quick up failed: "+string(out), http.StatusInternalServerError)
		return
	}

	var publicKey string
	for _, line := range strings.Split(req.ConfigText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PublicKey = ") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey = "))
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"name":      name,
		"publicKey": publicKey,
	})
}

func (s *Server) getAmneziaInterfaces(w http.ResponseWriter, r *http.Request) {
	dir := "/etc/amnezia/amneziawg"
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]string{})
		return
	}
	var result []map[string]string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		running := isAmneziaRunning(name)
		pubKey := ""
		address := ""
		handshake := ""
		rx := ""
		tx := ""
		if running {
			pubKey = getAmneziaPublicKey(name)
			address = getAmneziaAddress(name)
			handshake = getAmneziaHandshake(name)
			rx, tx = getAmneziaTransfer(name)
		}
		result = append(result, map[string]string{
			"name":      name,
			"running":   fmt.Sprintf("%v", running),
			"publicKey": pubKey,
			"address":   address,
			"handshake": handshake,
			"ping":      getAmneziaPing(name),
			"rx":        rx,
			"tx":        tx,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func isAmneziaRunning(name string) bool {
	_, err := exec.Command("awg", "show", name).CombinedOutput()
	return err == nil
}

func getAmneziaPublicKey(name string) string {
	out, _ := exec.Command("awg", "show", name).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public key: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "public key: "))
		}
	}
	return ""
}

func getAmneziaHandshake(name string) string {
	out, _ := exec.Command("awg", "show", name).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "latest handshake: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "latest handshake: "))
		}
	}
	return "никогда"
}

func getAmneziaTransfer(name string) (string, string) {
	out, _ := exec.Command("awg", "show", name).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "transfer: ") {
			rest := strings.TrimPrefix(line, "transfer: ")
			parts := strings.Split(rest, ", ")
			var rx, tx string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasSuffix(p, "received") {
					rx = strings.TrimSuffix(p, " received")
				} else if strings.HasSuffix(p, "sent") {
					tx = strings.TrimSuffix(p, " sent")
				}
			}
			return rx, tx
		}
	}
	return "0 B", "0 B"
}

func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return 0
	}
	valStr := parts[0]
	unit := ""
	if len(parts) > 1 {
		unit = parts[1]
	}
	var val float64
	var parseErr error
	if val, parseErr = strconv.ParseFloat(valStr, 64); parseErr != nil {
		return 0
	}
	switch strings.ToLower(unit) {
	case "kib", "kb", "k":
		return int64(val * 1024)
	case "mib", "mb", "m":
		return int64(val * 1024 * 1024)
	case "gib", "gb", "g":
		return int64(val * 1024 * 1024 * 1024)
	case "tib", "tb", "t":
		return int64(val * 1024 * 1024 * 1024 * 1024)
	default:
		return int64(val)
	}
}

func formatBytesAWG(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	u := 1024
	e := int(math.Log(float64(b)) / math.Log(float64(u)))
	div := int64(math.Pow(float64(u), float64(e)))
	val := float64(b) / float64(div)
	if val == math.Floor(val) {
		return fmt.Sprintf("%.0f %ciB", val, "KMGTPE"[e-1])
	}
	return fmt.Sprintf("%.1f %ciB", val, "KMGTPE"[e-1])
}

func getAmneziaAddress(name string) string {
	confPath := fmt.Sprintf("/etc/amnezia/amneziawg/%s.conf", name)
	data, err := os.ReadFile(confPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address = ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Address = "))
		}
	}
	return ""
}

func getAmneziaPing(name string) string {
	out, err := exec.Command("ping", "-c", "1", "-W", "1", "-I", name, "1.1.1.1").CombinedOutput()
	if err != nil {
		return "timeout"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "time=") {
			parts := strings.Split(line, "time=")
			if len(parts) > 1 {
				return strings.TrimSpace(strings.Split(parts[1], " ")[0])
			}
		}
	}
	return "timeout"
}

func (s *Server) manageAmneziaInterface(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	name := parts[0]
	var action string
	if len(parts) >= 2 {
		action = parts[1]
	}

	switch action {
	case "down":
		out, err := exec.Command("awg-quick", "down", name).CombinedOutput()
		if err != nil {
			http.Error(w, "awg-quick down failed: "+string(out), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	case "up":
		_, err := exec.Command("awg-quick", "up", name).CombinedOutput()
		if err != nil {
			http.Error(w, "awg-quick up failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	case "delete":
		exec.Command("awg-quick", "down", name).CombinedOutput()
		os.Remove(fmt.Sprintf("/etc/amnezia/amneziawg/%s.conf", name))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (s *Server) getDnsApplyStatus(w http.ResponseWriter, r *http.Request) {
	status := "idle"
	stBytes, _ := os.ReadFile("/tmp/dns-apply.status")
	status = strings.TrimSpace(string(stBytes))

	logBytes, _ := os.ReadFile("/tmp/dns-apply.log")
	logText := string(logBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"log":    logText,
	})
}
