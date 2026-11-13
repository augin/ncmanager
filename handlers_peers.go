package main

import (
	"encoding/json"
	"fmt"
	"github.com/skip2/go-qrcode"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
	if !decodeJSONBody(w, r, &req) {
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

	_ = generateWgConfig(cfg, peersCfg.Peers)

	if err := syncconfAddPeer(peer); err != nil {
		log.Printf("addPeer: syncconf failed: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(peer)
}

func (s *Server) removePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSONBody(w, r, &req) {
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

	publicKeyToRemove := peerToRemove.PublicKey

	filtered := peersCfg.Peers[:0]
	for _, p := range peersCfg.Peers {
		if p.ID != req.ID {
			filtered = append(filtered, p)
		}
	}
	peersCfg.Peers = filtered

	_ = savePeers(peersCfg)
	clearRouterCache(req.ID)
	cfg, _ := loadConfig(dataFile)
	_ = generateWgConfig(cfg, peersCfg.Peers)

	if err := syncconfRemovePeer(publicKeyToRemove); err != nil {
		log.Printf("removePeer: syncconf failed: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Phone          *string `json:"phone"`
		RouterDomain   string  `json:"routerDomain"`
		RouterLogin    string  `json:"routerLogin"`
		RouterPassword string  `json:"routerPassword"`
		Description    string  `json:"description"`
		Paid           *bool   `json:"paid"`
		VPNOnly        *bool   `json:"vpnOnly"`
		CreatedAt      string  `json:"createdAt"`
	}
	if !decodeJSONBody(w, r, &req) {
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
	if req.Name != "" {
		newName := strings.TrimSpace(req.Name)
		if newName == "" {
			http.Error(w, "peer name cannot be empty", http.StatusBadRequest)
			return
		}
		for i := range peersCfg.Peers {
			if peersCfg.Peers[i].ID != req.ID && strings.TrimSpace(peersCfg.Peers[i].Name) == newName {
				http.Error(w, "peer name already exists", http.StatusConflict)
				return
			}
		}
	}
	found := false
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == req.ID {
			if req.Name != "" {
				peersCfg.Peers[i].Name = strings.TrimSpace(req.Name)
			}
			if req.Phone != nil {
				peersCfg.Peers[i].Phone = strings.TrimSpace(*req.Phone)
			}
			if req.RouterDomain != "" {
				peersCfg.Peers[i].RouterDomain = req.RouterDomain
			}
			if req.RouterLogin != "" {
				peersCfg.Peers[i].RouterLogin = req.RouterLogin
			}
			if req.RouterPassword != "" {
				peersCfg.Peers[i].RouterPassword = req.RouterPassword
			}
			if req.Description != "" {
				peersCfg.Peers[i].Description = req.Description
			}
			if req.Paid != nil {
				peersCfg.Peers[i].Paid = *req.Paid
			}
			if req.VPNOnly != nil {
				peersCfg.Peers[i].VPNOnly = *req.VPNOnly
			}
			if req.CreatedAt != "" {
				if t, err := time.Parse(time.RFC3339, req.CreatedAt); err == nil {
					peersCfg.Peers[i].CreatedAt = t
				} else {
					http.Error(w, "invalid createdAt format, expected RFC3339", http.StatusBadRequest)
					return
				}
			}
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

// buildPeerConfig возвращает пир и сгенерированный WireGuard-конфиг клиента.

// buildPeerConfig возвращает пир и сгенерированный WireGuard-конфиг клиента.
func (s *Server) buildPeerConfig(id string) (*Peer, string, error) {
	peersCfg, err := loadPeers()
	if err != nil {
		return nil, "", err
	}
	peer := findPeer(peersCfg.Peers, id)
	if peer == nil {
		return nil, "", errPeerNotFound
	}
	globalCfg, _ := loadConfig(dataFile)
	return peer, generatePeerConfig(peer, resolveServerPublicKey(), s.iface, s.endpoint, s.wgPort, globalCfg.DNS), nil
}

func (s *Server) getPeerQR(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	_, peerConf, err := s.buildPeerConfig(id)
	if err != nil {
		peerConfigError(w, err)
		return
	}
	qr, err := qrcode.Encode(peerConf, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(qr)
}

func (s *Server) getPeerConfigText(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	_, peerConf, err := s.buildPeerConfig(id)
	if err != nil {
		peerConfigError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(peerConf))
}

func (s *Server) downloadPeerConfig(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	peer, peerConf, err := s.buildPeerConfig(id)
	if err != nil {
		peerConfigError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", sanitizeFilename(peer.Name)))
	w.Write([]byte(peerConf))
}

func generateKeeneticServerConfig(peer *Peer, serverPub, iface, endpoint string, wgPort int, subnet, wanIface string) string {
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
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", wgPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", strings.TrimSpace(serverPub)))
	b.WriteString(fmt.Sprintf("PostUp = iptables -A INPUT -p udp --dport %d -j ACCEPT || true; iptables -A FORWARD -i %s -o %%i -j ACCEPT || true; iptables -A FORWARD -i %%i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE || true; ip route add default dev %s table 110 || true; ip rule add iif %%i table 110 || true;\n", wgPort, wanIface, wanIface, wanIface))
	b.WriteString(fmt.Sprintf("PostDown = iptables -D INPUT -p udp --dport %d -j ACCEPT || true; iptables -D FORWARD -i %s -o %%i -j ACCEPT || true; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE || true; ip route del default dev %s table 110 || true; ip rule del iif %%i table 110 || true;\n", wgPort, wanIface, wanIface, wanIface))
	b.WriteString("SaveConfig = true\n")

	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("# %s\n", peer.Name))
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", peer.AllowedIPs))
	b.WriteString("PersistentKeepalive = 25\n")

	return b.String()
}

func (s *Server) importPeerToKeenetic(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	id, ok := peerIDFromPath(w, r)
	if !ok {
		return
	}

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	globalCfg, _ := loadConfig(dataFile)
	peer := findPeer(peersCfg.Peers, id)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	serverPub := resolveServerPublicKey()
	confContent := generatePeerConfig(peer, serverPub, s.iface, s.endpoint, s.wgPort, globalCfg.DNS)

	if !peer.HasRouterCreds() {
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
		s.wgPort,
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
		peer.RouterIfName = ifName
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
	id, ok := peerIDFromPath(w, r)
	if !ok {
		return
	}
	peer, peerConf, err := s.buildPeerConfig(id)
	if err != nil {
		peerConfigError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", sanitizeFilename(peer.Name)))
	w.Write([]byte(peerConf))
}

func (s *Server) configurePeerComponents(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
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
	peerPtr := findPeer(peersCfg.Peers, peerID)
	if peerPtr == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	peer := *peerPtr

	if !peer.HasRouterCreds() {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	globalCfg, _ := loadConfig(dataFile)

	os.WriteFile(filepath.Join(logDir, "components-apply.status"), []byte("running"), 0644)
	os.WriteFile(filepath.Join(logDir, "components-apply.log"), []byte("Запуск настройки компонентов...\n"), 0644)

	go func() {
		httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
		if err != nil {
			componentsAppendLog(fmt.Sprintf("❌ Ошибка подключения к %s: %v\n", peer.RouterDomain, err))
			os.WriteFile(filepath.Join(logDir, "components-apply.status"), []byte("failed"), 0644)
			return
		}

		serverPub := resolveServerPublicKey()

		res := configureRouterComponents(httpClient, baseURL, &peer, serverPub, s.endpoint, s.wgPort, globalCfg.WanInterface)

		var status string
		if res.Status == "error" {
			status = "failed"
		} else {
			status = "completed"
		}
		os.WriteFile(filepath.Join(logDir, "components-apply.status"), []byte(status), 0644)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) getComponentsApplyStatus(w http.ResponseWriter, r *http.Request) {
	status := "idle"
	stBytes, _ := os.ReadFile(filepath.Join(logDir, "components-apply.status"))
	status = strings.TrimSpace(string(stBytes))

	logBytes, _ := os.ReadFile(filepath.Join(logDir, "components-apply.log"))
	logText := string(logBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"log":    logText,
	})
}
