package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const routerCacheTTL = 15 * time.Minute

type routerCacheEntry struct {
	available bool
	model     string
	version   string
	ts        time.Time
}

var (
	routerCache   = make(map[string]*routerCacheEntry)
	routerCacheMu sync.RWMutex
)

func clearRouterCache(peerID string) {
	routerCacheMu.Lock()
	delete(routerCache, peerID)
	routerCacheMu.Unlock()
}

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
				Model string `json:"model"`
				Title string `json:"title"`
			} `json:"version"`
		} `json:"show"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", err
	}
	return resp.Show.Version.Model, resp.Show.Version.Title, nil
}

func (s *Server) checkPeerRouter(w http.ResponseWriter, r *http.Request) {
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

	if peer.RouterDomain == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"available": false, "model": "", "version": ""})
		return
	}

	routerCacheMu.RLock()
	entry, ok := routerCache[peerID]
	routerCacheMu.RUnlock()
	if ok && time.Since(entry.ts) < routerCacheTTL {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"available": entry.available,
			"model":     entry.model,
			"version":   entry.version,
		})
		return
	}

	var available bool
	var model, version string

	if peer.RouterLogin != "" && peer.RouterPassword != "" {
		httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
		if err != nil {
			available = false
		} else {
			m, v, err := s.getRouterInfo(httpClient, baseURL)
			if err != nil {
				available = false
			} else {
				available = true
				model = m
				version = v
			}
		}
	} else {
		available = checkRouterHTTPAvailability(peer.RouterDomain)
	}

	routerCacheMu.Lock()
	routerCache[peerID] = &routerCacheEntry{
		available: available,
		model:     model,
		version:   version,
		ts:        time.Now(),
	}
	routerCacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"available": available,
		"model":     model,
		"version":   version,
	})
}

func checkRouterHTTPAvailability(domain string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + domain + "/"
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}
