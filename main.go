package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
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
const wgConfigFile = "data/wg0.conf"

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
	Port      int    `json:"port"`
	Interface string `json:"interface"`
	Endpoint  string `json:"endpoint"`
	DNS       string `json:"dns"`
	Subnet    string `json:"subnet"`
	Peers     []Peer `json:"peers"`
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

	if err := generateWgConfig(cfg); err != nil {
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
	api.HandleFunc("/dns/preset", withAuth(server.applyDnsPreset))
	api.HandleFunc("/dns/status", withAuth(server.getDnsStatus))
	api.HandleFunc("/dns/routes", withAuth(server.configurePeerDnsRoutes))
	api.HandleFunc("/server/start", withAuth(server.startServer))
	api.HandleFunc("/server/stop", withAuth(server.stopServer))
	api.HandleFunc("/server/restart", withAuth(server.restartServer))
	api.HandleFunc("/keys/generate", withAuth(generateKeys))
	api.HandleFunc("/login", loginHandler)
	api.HandleFunc("/logout", withAuth(logoutHandler))
	api.HandleFunc("/logs", withAuth(server.getLogs))
	api.HandleFunc("/router/dump/", withAuth(server.dumpRouterRCI))
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
		Peers:     []Peer{},
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
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(cfg)
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

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig(dataFile)
	if err != nil {
		http.Error(w, "failed to load config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var req Config
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
	cfg.Port = req.Port
	cfg.Interface = req.Interface
	cfg.DNS = req.DNS
	cfg.Subnet = req.Subnet
	cfg.Endpoint = resolveEndpoint(req.Endpoint)
	if len(req.Peers) > 0 {
		cfg.Peers = req.Peers
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

	if err := generateWgConfig(cfg); err != nil {
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
	cfg, err := loadConfig(dataFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = syncPeersWithWireGuard(cfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg.Peers)
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

	cfg, _ := loadConfig(dataFile)
	allowedIP, err := nextAvailableIP(cfg.Peers, cfg.Subnet)
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
	cfg.Peers = append(cfg.Peers, peer)

	if err := saveConfig(dataFile, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = addPeerWireGuard(peer)
	_ = generateWgConfig(cfg)

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

	cfg, _ := loadConfig(dataFile)
	var peerToRemove *Peer
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == req.ID {
			peerToRemove = &cfg.Peers[i]
			break
		}
	}
	if peerToRemove == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	filtered := cfg.Peers[:0]
	for _, p := range cfg.Peers {
		if p.ID != req.ID {
			filtered = append(filtered, p)
		}
	}
	cfg.Peers = filtered

	_ = saveConfig(dataFile, cfg)
	if err := removePeerWireGuard(peerToRemove.PublicKey); err != nil {
		log.Printf("removePeer wg set failed: %v", err)
	}
	_ = generateWgConfig(cfg)

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

	cfg, _ := loadConfig(dataFile)
	found := false
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == req.ID {
			cfg.Peers[i].RouterDomain = req.RouterDomain
			cfg.Peers[i].RouterLogin = req.RouterLogin
			if req.RouterPassword != "" {
				cfg.Peers[i].RouterPassword = req.RouterPassword
			}
			cfg.Peers[i].Description = req.Description
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	_ = saveConfig(dataFile, cfg)

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
	cfg, _ := loadConfig(dataFile)
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peer := &cfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, cfg.DNS)
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
	log.Printf("QR peer not found id=%s total=%d", id, len(cfg.Peers))
	http.Error(w, "peer not found", http.StatusNotFound)
}

func (s *Server) getPeerConfigText(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	log.Printf("ConfigText: path=%s rawQuery=%s id=%s", r.URL.Path, r.URL.RawQuery, id)
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	cfg, _ := loadConfig(dataFile)
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peer := &cfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, cfg.DNS)
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
	cfg, _ := loadConfig(dataFile)
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peer := &cfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, cfg.DNS)
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

func generateKeeneticServerConfig(peer *Peer, serverPub, iface, endpoint string, port int, subnet string) string {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil || ipnet == nil {
		ipnet = &net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(24, 32)}
	}
	serverIP := ipnet.IP.To4()
	serverIP[3]++
	serverAddr := fmt.Sprintf("%s/%d", serverIP.String(), getCIDRPrefix(ipnet))
	wanIface := "eth0"
	if iface == "wg0" {
		wanIface = "eth0"
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", strings.TrimSpace(serverPub)))
	b.WriteString(fmt.Sprintf("PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", wanIface))
	b.WriteString(fmt.Sprintf("PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", wanIface))
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

	cfg, _ := loadConfig(dataFile)
	peerIdx := -1
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peerIdx = i
			break
		}
	}
	if peerIdx < 0 {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := &cfg.Peers[peerIdx]

	serverPub := getActualServerPublicKey()
	if serverPub == "" {
		serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
		serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
	}
	confContent := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, cfg.DNS)

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	result, err := importWireGuardConfigToRouter(
		"http://"+peer.RouterDomain,
		peer.RouterLogin,
		peer.RouterPassword,
		[]byte(confContent),
		sanitizeFilename(peer.Name)+".conf",
		peer.AllowedIPs,
		s.endpoint,
		s.port,
	)
	if err != nil {
		log.Printf("keenetic import failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router import failed: %v", err), http.StatusBadGateway)
		return
	}

	// Store the created interface name for next time
	ifName := result.Created
	if ifName == "" {
		ifName = result.Intersects
	}
	if ifName != "" && ifName != peer.RouterIfName {
		cfg.Peers[peerIdx].RouterIfName = ifName
		_ = saveConfig(dataFile, cfg)
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
	cfg, _ := loadConfig(dataFile)
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peer := &cfg.Peers[i]
			serverPub := getActualServerPublicKey()
			if serverPub == "" {
				serverPrivBytes, _ := loadPrivateKey("data/server_private.key")
				serverPub, _ = getPublicKeyFromPrivate(serverPrivBytes)
			}
			peerConf := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.port, cfg.DNS)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", sanitizeFilename(peer.Name)))
			w.Write([]byte(peerConf))
			return
		}
	}
	http.Error(w, "peer not found", http.StatusNotFound)
}

func (s *Server) configurePeerDns(w http.ResponseWriter, r *http.Request) {
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

	cfg, _ := loadConfig(dataFile)
	peerIdx := -1
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peerIdx = i
			break
		}
	}
	if peerIdx < 0 {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := &cfg.Peers[peerIdx]

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := keeneticAuth(httpClient, "http://"+peer.RouterDomain, peer.RouterLogin, peer.RouterPassword); err != nil {
		log.Printf("keenetic dns auth failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	var messages []string
	if err := keeneticSetupSecureDns(httpClient, "http://"+peer.RouterDomain); err != nil {
		messages = append(messages, "⚠️ DNS: "+err.Error())
	} else {
		messages = append(messages, "✅ DNS-серверы добавлены")
	}

	if err := keeneticSave(httpClient, "http://"+peer.RouterDomain); err != nil {
		messages = append(messages, "⚠️ сохранение: "+err.Error())
	} else {
		messages = append(messages, "✅ конфигурация сохранена")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "ok",
		"messages": messages,
		"peer":     peer.Name,
	})
}

func (s *Server) configurePeerDnsRoutes(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	cfg, _ := loadConfig(dataFile)
	peerIdx := -1
	for i := range cfg.Peers {
		if cfg.Peers[i].ID == id {
			peerIdx = i
			break
		}
	}
	if peerIdx < 0 {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := &cfg.Peers[peerIdx]

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := keeneticAuth(httpClient, "http://"+peer.RouterDomain, peer.RouterLogin, peer.RouterPassword); err != nil {
		log.Printf("keenetic dns-routes auth failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	wanIface := "FastEthernet0/Vlan1"
	if err := keeneticSetDnsRoutes(httpClient, "http://"+peer.RouterDomain, wanIface, req.Enabled); err != nil {
		log.Printf("keenetic set dns-routes failed: %v", err)
		http.Error(w, fmt.Sprintf("set dns-routes failed: %v", err), http.StatusBadGateway)
		return
	}

	if err := keeneticSave(httpClient, "http://"+peer.RouterDomain); err != nil {
		log.Printf("keenetic save failed: %v", err)
		http.Error(w, fmt.Sprintf("save failed: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"enabled": req.Enabled,
		"wanIface": wanIface,
		"peer":    peer.Name,
	})
}

func (s *Server) applyDnsPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RouterDomain   string `json:"routerDomain"`
		RouterLogin    string `json:"routerLogin"`
		RouterPassword string `json:"routerPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.RouterDomain == "" || req.RouterLogin == "" || req.RouterPassword == "" {
		http.Error(w, "router credentials required", http.StatusBadRequest)
		return
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := keeneticAuth(httpClient, "http://"+req.RouterDomain, req.RouterLogin, req.RouterPassword); err != nil {
		log.Printf("dns preset auth failed for %s: %v", req.RouterDomain, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	var messages []string
	if err := keeneticSetupSecureDns(httpClient, "http://"+req.RouterDomain); err != nil {
		messages = append(messages, "⚠️ DNS: "+err.Error())
	} else {
		messages = append(messages, "✅ DNS-серверы добавлены")
	}
	if err := keeneticSave(httpClient, "http://"+req.RouterDomain); err != nil {
		messages = append(messages, "⚠️ сохранение: "+err.Error())
	} else {
		messages = append(messages, "✅ конфигурация сохранена")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "messages": messages})
}

func (s *Server) getDnsStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RouterDomain   string `json:"routerDomain"`
		RouterLogin    string `json:"routerLogin"`
		RouterPassword string `json:"routerPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.RouterDomain == "" || req.RouterLogin == "" || req.RouterPassword == "" {
		http.Error(w, "router credentials required", http.StatusBadRequest)
		return
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := keeneticAuth(httpClient, "http://"+req.RouterDomain, req.RouterLogin, req.RouterPassword); err != nil {
		log.Printf("dns status auth failed for %s: %v", req.RouterDomain, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	resp, err := httpClient.Get("http://" + req.RouterDomain + "/rci/")
	if err != nil {
		http.Error(w, fmt.Sprintf("rci get failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		http.Error(w, fmt.Sprintf("parse failed: %v", err), http.StatusBadGateway)
		return
	}

	dnsProxy := parsed["dns-proxy"]
	if dnsProxy == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"upstreams": []any{}})
		return
	}

	dnsProxyMap, ok := dnsProxy.(map[string]any)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"upstreams": []any{}})
		return
	}

	tls := dnsProxyMap["tls"]
	if tls == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"upstreams": []any{}})
		return
	}

	tlsMap, ok := tls.(map[string]any)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"upstreams": []any{}})
		return
	}

	upstreams, _ := tlsMap["upstream"].([]any)
	if upstreams == nil {
		upstreams = []any{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"upstreams": upstreams})
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
	cfg, _ := loadConfig(dataFile)
	if len(cfg.Peers) == 0 {
		http.Error(w, "no peers configured", http.StatusBadRequest)
		return
	}
	peer := &cfg.Peers[0]
	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured", http.StatusBadRequest)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	ifaceQuery := ""
	if len(parts) > 3 && parts[3] != "" {
		ifaceQuery = parts[3]
	}
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	if err := keeneticAuth(httpClient, "http://"+peer.RouterDomain, peer.RouterLogin, peer.RouterPassword); err != nil {
		http.Error(w, "router auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if ifaceQuery != "" {
		postPayload := map[string]any{ifaceQuery: nil}
		if data, _, err := keeneticRciPost(httpClient, "http://"+peer.RouterDomain, postPayload); err == nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write(data)
		} else {
			http.Error(w, "rci query failed: "+err.Error(), http.StatusBadGateway)
		}
		return
	}
	resp, err := httpClient.Get("http://" + peer.RouterDomain + "/rci/")
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

func syncPeersWithWireGuard(cfg *Config) error {
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
	for i := range cfg.Peers {
		if p, ok := peerMap[cfg.Peers[i].PublicKey]; ok {
			cfg.Peers[i].LastHandshake = p.LastHandshake
			cfg.Peers[i].TransferRx = p.TransferRx
			cfg.Peers[i].TransferTx = p.TransferTx
			cfg.Peers[i].Endpoint = p.Endpoint
		}
	}
	return nil
}

func generateWgConfig(cfg *Config) error {
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

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.Port))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPriv))
	b.WriteString(fmt.Sprintf("PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"))
	b.WriteString(fmt.Sprintf("PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n"))

	for _, p := range cfg.Peers {
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
