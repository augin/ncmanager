package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (s *Server) getPeerRouterInfo(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return
	}
	peerID := parts[3]

	peersCfg, _ := loadPeers()
	var peer *Peer
	for i := range peersCfg.Peers {
		if peersCfg.Peers[i].ID == peerID {
			peer = &peersCfg.Peers[i]
			break
		}
	}
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
		http.Error(w, "router credentials not configured", http.StatusBadRequest)
		return
	}

	httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
	if err != nil {
		http.Error(w, "auth failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	model, version, err := s.getRouterInfo(httpClient, baseURL)
	if err != nil {
		http.Error(w, "get router info failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"model":   model,
		"version": version,
	})
}

func (s *Server) getRouterInfo(httpClient *http.Client, baseURL string) (model, version string, err error) {
	// Try version first
	payload := map[string]any{"show": map[string]any{"version": true}}
	data, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err == nil && status == http.StatusOK {
		log.Printf("RCI version: %s", string(data))
		var resp struct{ Show struct{ Version string } }
		if jsonErr := json.Unmarshal(data, &resp); jsonErr == nil && resp.Show.Version != "" {
			return "", resp.Show.Version, nil
		}
	}
	// Try platform for model
	payload = map[string]any{"show": map[string]any{"platform": true}}
	data, status, err = keeneticRciPost(httpClient, baseURL, payload)
	if err == nil && status == http.StatusOK {
		log.Printf("RCI platform: %s", string(data))
		var resp struct{ Show struct{ Platform string `json:"platform"` } }
		if jsonErr := json.Unmarshal(data, &resp); jsonErr == nil && resp.Show.Platform != "" {
			return resp.Show.Platform, "", nil
		}
	}
	// Try hardware info
	payload = map[string]any{"show": map[string]any{"hardware": true}}
	data, status, err = keeneticRciPost(httpClient, baseURL, payload)
	if err == nil && status == http.StatusOK {
		log.Printf("RCI hardware: %s", string(data))
		var resp struct {
			Show struct {
				Model string `json:"model"`
				Ver   string `json:"version"`
			} `json:"hardware"`
		}
		if jsonErr := json.Unmarshal(data, &resp); jsonErr == nil {
			return resp.Show.Model, resp.Show.Ver, nil
		}
	}
	return "", "", fmt.Errorf("all RCI queries failed")
}