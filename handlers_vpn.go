package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) dumpRouterRCI(w http.ResponseWriter, r *http.Request) {
	peersCfg, _ := loadPeers()
	if len(peersCfg.Peers) == 0 {
		http.Error(w, "no peers configured", http.StatusBadRequest)
		return
	}
	peer := &peersCfg.Peers[0]
	if !peer.HasRouterCreds() {
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

func (s *Server) getDnsApplyStatus(w http.ResponseWriter, r *http.Request) {
	status := "idle"
	stBytes, _ := os.ReadFile(filepath.Join(logDir, "dns-apply.status"))
	status = strings.TrimSpace(string(stBytes))

	logBytes, _ := os.ReadFile(filepath.Join(logDir, "dns-apply.log"))
	logText := string(logBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"log":    logText,
	})
}

func (s *Server) applyPeerVpn(w http.ResponseWriter, r *http.Request) {
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
	peer := findPeer(peersCfg.Peers, id)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	if !peer.HasRouterCreds() {
		http.Error(w, "router credentials not configured", http.StatusBadRequest)
		return
	}

	statusFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.status"), id)
	logFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.log"), id)
	os.WriteFile(statusFile, []byte("running"), 0644)
	os.WriteFile(logFile, []byte(""), 0644)

	go func(p *Peer) {
		serverPub := resolveServerPublicKey()
		confContent := generatePeerConfig(p, serverPub, "", s.endpoint, s.wgPort, "")
		logText := ""
		appendLog := func(line string) {
			logText += line + "\n"
			os.WriteFile(logFile, []byte(logText), 0644)
		}

		appendLog("Подключение к " + p.RouterDomain + "...")
		_, baseURL, err := keeneticSetupClient(p.RouterDomain, p.RouterLogin, p.RouterPassword)
		if err != nil {
			appendLog("❌ Ошибка подключения: " + err.Error())
			os.WriteFile(statusFile, []byte("failed"), 0644)
			return
		}

		result, err := importWireGuardConfigToRouter(
			baseURL, p.RouterLogin, p.RouterPassword,
			[]byte(confContent),
			sanitizeFilename(p.Name)+".conf",
			p.AllowedIPs, "0.0.0.0/0", s.endpoint, s.wgPort,
		)
		if err != nil {
			appendLog("❌ Ошибка импорта: " + err.Error())
			os.WriteFile(statusFile, []byte("failed"), 0644)
			return
		}

		for _, msg := range result.Messages {
			appendLog("   ↳ " + msg)
		}

		ifName := result.Created
		if ifName == "" {
			ifName = result.Intersects
		}
		if ifName == "" {
			appendLog("❌ Интерфейс не создан")
			os.WriteFile(statusFile, []byte("failed"), 0644)
			return
		}

		appendLog("✅ Интерфейс создан: " + ifName)

		peersCfg, _ := loadPeers()
		for i := range peersCfg.Peers {
			if peersCfg.Peers[i].ID == p.ID {
				peersCfg.Peers[i].RouterIfName = ifName
				peersCfg.Peers[i].VPNActive = true
				_ = savePeers(peersCfg)
				break
			}
		}
		os.WriteFile(statusFile, []byte("completed"), 0644)
	}(peer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) removePeerVpn(w http.ResponseWriter, r *http.Request) {
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
	peer := findPeer(peersCfg.Peers, id)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.RouterIfName == "" {
		http.Error(w, "no router interface configured", http.StatusBadRequest)
		return
	}

	statusFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.status"), id)
	logFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.log"), id)
	os.WriteFile(statusFile, []byte("running"), 0644)
	os.WriteFile(logFile, []byte(""), 0644)

	go func(p *Peer) {
		logText := ""
		appendLog := func(line string) {
			logText += line + "\n"
			os.WriteFile(logFile, []byte(logText), 0644)
		}

		appendLog("Подключение к " + p.RouterDomain + "...")
		client, baseURL, err := keeneticSetupClient(p.RouterDomain, p.RouterLogin, p.RouterPassword)
		if err != nil {
			appendLog("❌ Ошибка подключения: " + err.Error())
			os.WriteFile(statusFile, []byte("failed"), 0644)
			return
		}

		appendLog("Удаление интерфейса " + p.RouterIfName + "...")
		if err := keeneticRemoveInterface(client, baseURL, p.RouterIfName); err != nil {
			appendLog("❌ Ошибка удаления: " + err.Error())
			os.WriteFile(statusFile, []byte("failed"), 0644)
			return
		}

		appendLog("✅ Интерфейс удалён")

		peersCfg, _ := loadPeers()
		for i := range peersCfg.Peers {
			if peersCfg.Peers[i].ID == p.ID {
				peersCfg.Peers[i].RouterIfName = ""
				peersCfg.Peers[i].VPNActive = false
				_ = savePeers(peersCfg)
				break
			}
		}
		os.WriteFile(statusFile, []byte("completed"), 0644)
	}(peer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) getPeerVpnStatus(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	id := parts[3]

	statusFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.status"), id)
	logFile := fmt.Sprintf(filepath.Join(logDir, "peer-vpn-%s.log"), id)

	status := "idle"
	stBytes, _ := os.ReadFile(statusFile)
	if string(stBytes) != "" {
		status = strings.TrimSpace(string(stBytes))
	}

	logBytes, _ := os.ReadFile(logFile)
	logText := string(logBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"log":    logText,
	})
}
