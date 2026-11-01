package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
	routes, _ := loadDnsRoutes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"wgPort":              cfg.WGPort,
		"httpPort":            cfg.HttpPort,
		"interface":           cfg.Interface,
		"wanInterface":        cfg.WanInterface,
		"endpoint":            cfg.Endpoint,
		"dns":                 cfg.DNS,
		"subnet":              cfg.Subnet,
		"interfaceIP":         getInterfaceIP(cfg.Subnet),
		"postUp":              autogenPostUp(cfg.WanInterface, cfg.WGPort),
		"postDown":            autogenPostDown(cfg.WanInterface, cfg.WGPort),
		"tlsEnabled":          cfg.TLSEnabled,
		"tlsHost":             cfg.TLSHost,
		"tlsCache":            cfg.TLSCache,
		"serverName":          cfg.ServerName,
		"routerCheckTimeout":  cfg.RouterCheckTimeout,
		"routerCheckInterval": cfg.RouterCheckInterval,
		"routerCacheTTL":      cfg.RouterCacheTTL,
		"peers":               peersCfg.Peers,
		"dnsRoutes":           routes,
	})
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if !decodeJSONBody(w, r, &req) {
		return
	}
	oldCfg, _ := loadConfig(dataFile)

	s.mu.Lock()
	cfg := oldCfg
	if cfg == nil {
		cfg = &Config{}
	}
	if v, ok := req["wgPort"].(float64); ok {
		cfg.WGPort = int(v)
	}
	if v, ok := req["httpPort"].(float64); ok {
		p := int(v)
		if p < 1 || p > 65535 {
			s.mu.Unlock()
			http.Error(w, "invalid httpPort: must be 1-65535", http.StatusBadRequest)
			return
		}
		cfg.HttpPort = p
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
	subnetChanged := false
	if raw, ok := req["subnet"]; ok {
		if s, ok := raw.(string); ok && s != "" && s != oldCfg.Subnet {
			cfg.Subnet = s
			subnetChanged = true
		}
	}
	cfg.PostUp = ""
	cfg.PostDown = ""
	if v, ok := req["endpoint"].(string); ok {
		cfg.Endpoint = resolveEndpoint(v)
	}
	if v, ok := req["tlsEnabled"].(bool); ok {
		cfg.TLSEnabled = v
	}
	if v, ok := req["tlsHost"].(string); ok {
		cfg.TLSHost = strings.TrimSpace(v)
	}
	if v, ok := req["tlsCache"].(string); ok {
		cfg.TLSCache = strings.TrimSpace(v)
	}
	if v, ok := req["serverName"].(string); ok && v != "" {
		cfg.ServerName = strings.TrimSpace(v)
	} else {
		cfg.ServerName = ""
	}
	if v, ok := req["routerCheckTimeout"].(float64); ok && v > 0 {
		cfg.RouterCheckTimeout = int(v)
	}
	if v, ok := req["routerCheckInterval"].(float64); ok && v > 0 {
		cfg.RouterCheckInterval = int(v)
	}
	if v, ok := req["routerCacheTTL"].(float64); ok && v > 0 {
		cfg.RouterCacheTTL = int(v)
	}

	if err := saveConfig(dataFile, cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.wgPort = cfg.WGPort
	s.iface = cfg.Interface
	s.endpoint = cfg.Endpoint
	s.mu.Unlock()

	if cfg.RouterCacheTTL > 0 {
		setRouterCacheTTLSeconds(cfg.RouterCacheTTL)
	}

	peersCfg, _ := loadPeers()
	if subnetChanged {
		for i := range peersCfg.Peers {
			ip, err := nextAvailableIP(peersCfg.Peers, cfg.Subnet)
			if err != nil {
				log.Printf("recalc IP for peer %s: %v", peersCfg.Peers[i].ID, err)
				continue
			}
			peersCfg.Peers[i].AllowedIPs = ip
		}
	}
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

	// Сначала гасим интерфейс со СТАРЫМ конфигом: wg-quick down читает
	// /etc/wireguard/wg0.conf на момент вызова. Если записать новый конфиг раньше,
	// down выполнит PostDown нового конфига, а iptables-правила и маршрут
	// по умолчанию в table 110 старого WAN-интерфейса останутся в системе —
	// из-за них новый интерфейс выхода не применяется.
	s.stopServerDirect()

	if err := generateWgConfig(cfg, peersCfg.Peers); err != nil {
		log.Printf("saveConfig: generate wg config: %v", err)
		s.startServerDirect() // поднимаем обратно со старым конфигом
		http.Error(w, fmt.Sprintf("failed to generate wg config: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("saveConfig: wg config generated subnet=%s peers=%d", cfg.Subnet, len(peersCfg.Peers))

	if err := s.startServerDirect(); err != nil {
		http.Error(w, fmt.Sprintf("failed to restart server: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("saveConfig: wg restarted subnet=%s", cfg.Subnet)

	if err := configureUfwRoutes(cfg); err != nil {
		log.Printf("saveConfig: ufw routes: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "interfaceIP": getInterfaceIP(cfg.Subnet)})
}

func (s *Server) saveGeneralConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if !decodeJSONBody(w, r, &req) {
		return
	}
	s.mu.Lock()
	cfg, _ := loadConfig(dataFile)
	if cfg == nil {
		cfg = &Config{}
	}
	if v, ok := req["serverName"].(string); ok && v != "" {
		cfg.ServerName = strings.TrimSpace(v)
	} else {
		cfg.ServerName = ""
	}
	if v, ok := req["httpPort"].(float64); ok {
		p := int(v)
		if p < 1 || p > 65535 {
			s.mu.Unlock()
			http.Error(w, "invalid httpPort: must be 1-65535", http.StatusBadRequest)
			return
		}
		cfg.HttpPort = p
	}
	if v, ok := req["tlsEnabled"].(bool); ok {
		cfg.TLSEnabled = v
	}
	if v, ok := req["tlsHost"].(string); ok {
		cfg.TLSHost = strings.TrimSpace(v)
	}
	if v, ok := req["tlsCache"].(string); ok {
		cfg.TLSCache = strings.TrimSpace(v)
	}
	if v, ok := req["routerCheckTimeout"].(float64); ok && v > 0 {
		cfg.RouterCheckTimeout = int(v)
	}
	if v, ok := req["routerCheckInterval"].(float64); ok && v > 0 {
		cfg.RouterCheckInterval = int(v)
	}
	if v, ok := req["routerCacheTTL"].(float64); ok && v > 0 {
		cfg.RouterCacheTTL = int(v)
	}
	if err := saveConfig(dataFile, cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	if cfg.RouterCacheTTL > 0 {
		setRouterCacheTTLSeconds(cfg.RouterCacheTTL)
	}
	log.Printf("saveGeneralConfig: serverName=%s httpPort=%d", cfg.ServerName, cfg.HttpPort)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	data, err := os.ReadFile(filepath.Join(logDir, "ncmanager.log"))
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
	out, err := execWithTimeout(30*time.Second, "wg-quick", "up", s.configPath)
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
	out, _ := execWithTimeout(30*time.Second, "wg-quick", "down", path)
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
	s.stopServerDirect()
	return s.startServerDirect()
}

// stopServerDirect гасит WireGuard-интерфейс: wg-quick down (PostDown выполняется
// из текущего, ещё не перезаписанного конфига) + принудительное удаление ссылки.
// Вызывать ДО перезаписи wg0.conf — иначе PostDown старого интерфейса не отработает.
func (s *Server) stopServerDirect() {
	s.mu.Lock()
	path := s.configPath
	iface := s.iface
	s.mu.Unlock()
	if iface == "" {
		iface = "wg0"
	}
	downOut, downErr := execWithTimeout(30*time.Second, "wg-quick", "down", path)
	if downErr != nil {
		log.Printf("wg-quick down: %s", string(downOut))
	}
	execWithTimeout(5*time.Second, "ip", "link", "del", "dev", iface)
	time.Sleep(700 * time.Millisecond)
}

// startServerDirect поднимает WireGuard-интерфейс по действующему wg0.conf.
func (s *Server) startServerDirect() error {
	s.mu.Lock()
	path := s.configPath
	s.mu.Unlock()
	out, err := execWithTimeout(30*time.Second, "wg-quick", "up", path)
	if err != nil {
		msg := string(out)
		log.Printf("wg-quick up failed: %s", msg)
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

func (s *Server) restartService(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "systemctl", "restart", "ncmanager")
		cmd.Run()
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"version": appVersion})
}
