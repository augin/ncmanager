package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func keeneticSetupSecureDns(httpClient *http.Client, baseURL string) error {
	dnsServers := []struct {
		address string
		sni     string
		domain  string
	}{
		{"9.9.9.9", "dns.quad9.net", ""},
		{"1.1.1.1", "cloudflare-dns.com", ""},
		{"77.88.8.8", "common.dot.dns.yandex.net", "ru"},
		{"77.88.8.8", "common.dot.dns.yandex.net", "su"},
		{"77.88.8.8", "common.dot.dns.yandex.net", "xn--p1ai"},
	}

	addressesToDelete := make(map[string]bool)
	for _, srv := range dnsServers {
		addressesToDelete[srv.address] = true
	}

	for addr := range addressesToDelete {
		delPayload := map[string]any{
			"dns-proxy": map[string]any{
				"tls": map[string]any{
					"upstream": []any{map[string]any{"address": addr, "no": true}},
				},
			},
		}
		var delStatus int
		var delErr error
		_, delStatus, delErr = keeneticRciPost(httpClient, baseURL, delPayload)
		if delErr != nil {
			return fmt.Errorf("delete dns upstream %s failed: %w", addr, delErr)
		}
		if delStatus != http.StatusOK {
			return fmt.Errorf("delete dns upstream %s failed (HTTP %d)", addr, delStatus)
		}
		time.Sleep(50 * time.Millisecond)
	}

	var upstreams []any
	for _, srv := range dnsServers {
		upstream := map[string]any{"address": srv.address}
		if srv.sni != "" {
			upstream["fqdn"] = srv.sni
		}
		if srv.domain != "" {
			upstream["domain"] = srv.domain
		}
		upstreams = append(upstreams, upstream)
	}

	payload := map[string]any{
		"dns-proxy": map[string]any{
			"tls": map[string]any{
				"upstream": upstreams,
			},
		},
	}
	_, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("add dns tls failed (HTTP %d)", status)
	}
	time.Sleep(30 * time.Millisecond)
	return nil
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

	peersCfg, err := loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured for this peer", http.StatusBadRequest)
		return
	}

	httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
	if err != nil {
		log.Printf("keenetic dns auth failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	var messages []string
	if err := keeneticSetupSecureDns(httpClient, baseURL); err != nil {
		messages = append(messages, "⚠️ DNS: "+err.Error())
	} else {
		messages = append(messages, "✅ DNS-серверы добавлены")
	}

	if err := keeneticSave(httpClient, baseURL); err != nil {
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
