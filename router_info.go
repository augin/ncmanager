package main

import (
	"encoding/json"
	"fmt"
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
	payload := map[string]any{"show": map[string]any{"version": true}}
	data, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil || status != http.StatusOK {
		return "", "", fmt.Errorf("RCI failed: %v", err)
	}
	var resp struct {
		Show struct {
			Version struct {
				Model  string `json:"model"`
				Title  string `json:"title"`
			} `json:"version"`
		} `json:"show"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", err
	}
	return resp.Show.Version.Model, resp.Show.Version.Title, nil
}