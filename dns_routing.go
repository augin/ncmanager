package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type DnsRoute struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Subnets   []string `json:"subnets,omitempty"`
	Enabled   bool     `json:"enabled"`
	Color     string   `json:"color,omitempty"`
	TunnelID  string   `json:"tunnelId,omitempty"`
}

var cyrTranslitSlug = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "yo",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "sch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

func sanitizeGroupSlug(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		if tr, ok := cyrTranslitSlug[r]; ok {
			b.WriteString(tr)
		} else if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	s = strings.Trim(s, "_")
	if len(s) > 20 {
		s = s[:20]
		s = strings.TrimRight(s, "_")
	}
	return s
}

func keeneticSetupSecureDns(httpClient *http.Client, baseURL string) error {
	dnsServers := []struct {
		address string
		sni     string
	}{
		{"9.9.9.9", "dns.quad9.net"},
		{"1.1.1.1", "cloudflare-dns.com"},
		{"common.dot.dns.yandex.net", "ru"},
		{"common.dot.dns.yandex.net", "su"},
		{"common.dot.dns.yandex.net", "xn--p1ai"},
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
		time.Sleep(150 * time.Millisecond)
	}

	var upstreams []any
	for _, srv := range dnsServers {
		upstream := map[string]any{"address": srv.address}
		if srv.sni != "" {
			upstream["fqdn"] = srv.sni
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
	time.Sleep(200 * time.Millisecond)
	return nil
}

type routeApply struct {
	Name    string
	Domains []string
	Subnets []string
	Enabled bool
}

func keeneticApplyDnsRoutes(httpClient *http.Client, baseURL, wgIface string, routes []routeApply) error {
	existingGroups, err := keeneticGetObjectGroups(httpClient, baseURL)
	if err != nil {
		return fmt.Errorf("read existing groups: %w", err)
	}

	activeSlugs := make(map[string]bool)
	for _, route := range routes {
		slug := sanitizeGroupSlug(route.Name)
		if slug == "" {
			slug = "route"
		}
		activeSlugs[slug] = true
	}

	for _, g := range existingGroups {
		slug := g
		if idx := strings.LastIndex(g, "_p"); idx > 0 {
			slug = g[:idx]
		}
		if !activeSlugs[slug] {
			log.Printf("cleaning orphaned group: %s (slug=%s)", g, slug)
			delPayload := map[string]any{
				"object-group": map[string]any{
					"fqdn": map[string]any{g: map[string]any{"no": true}},
				},
			}
			_, status, err := keeneticRciPost(httpClient, baseURL, delPayload)
			if err != nil {
				log.Printf("delete orphaned group %s: %v", g, err)
			} else if status != http.StatusOK {
				log.Printf("delete orphaned group %s: HTTP %d", g, status)
			}
			time.Sleep(150 * time.Millisecond)

			delRoutePayload := map[string]any{
				"dns-proxy": map[string]any{
					"route": []any{map[string]any{"group": g, "interface": wgIface, "no": true}},
				},
			}
			_, status, err = keeneticRciPost(httpClient, baseURL, delRoutePayload)
			if err != nil {
				log.Printf("delete orphaned route for %s: %v", g, err)
			} else if status != http.StatusOK {
				log.Printf("delete orphaned route for %s: HTTP %d", g, status)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	for _, route := range routes {
		slug := sanitizeGroupSlug(route.Name)
		if slug == "" {
			slug = "route"
		}

		oldNames := make([]string, 0)
		for _, g := range existingGroups {
			if strings.HasPrefix(g, slug+"_p") {
				oldNames = append(oldNames, g)
			}
		}

		if len(oldNames) > 0 {
			delPayload := map[string]any{
				"object-group": map[string]any{
					"fqdn": func() map[string]any {
						m := make(map[string]any)
						for _, n := range oldNames {
							m[n] = map[string]any{"no": true}
						}
						return m
					}(),
				},
			}
			_, status, err := keeneticRciPost(httpClient, baseURL, delPayload)
			if err != nil {
				return fmt.Errorf("delete old groups for %s: %w", route.Name, err)
			}
			if status != http.StatusOK {
				log.Printf("RCI delete old groups for %s: HTTP %d", route.Name, status)
			}
			time.Sleep(150 * time.Millisecond)

			for _, n := range oldNames {
				delRoutePayload := map[string]any{
					"dns-proxy": map[string]any{
						"route": []any{map[string]any{"group": n, "interface": wgIface, "no": true}},
					},
				}
				_, status, err := keeneticRciPost(httpClient, baseURL, delRoutePayload)
				if err != nil {
					return fmt.Errorf("delete old route %s: %w", n, err)
				}
				if status != http.StatusOK {
					log.Printf("RCI delete old route %s: HTTP %d", n, status)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		items := make([]string, 0, len(route.Domains)+len(route.Subnets))
		items = append(items, route.Domains...)
		items = append(items, route.Subnets...)
		if len(items) == 0 {
			continue
		}

		const chunkSize = 300
		var chunks [][]string
		for i := 0; i < len(items); i += chunkSize {
			end := i + chunkSize
			if end > len(items) {
				end = len(items)
			}
			chunks = append(chunks, items[i:end])
		}

		for chunkIdx, chunk := range chunks {
			groupName := fmt.Sprintf("%s_p%d", slug, chunkIdx+1)

			includes := make([]any, len(chunk))
			for i, item := range chunk {
				includes[i] = map[string]any{"address": item}
			}

			groupPayload := map[string]any{
				"object-group": map[string]any{
					"fqdn": map[string]any{
						groupName: map[string]any{
							"include": includes,
						},
					},
				},
			}
			_, status, err := keeneticRciPost(httpClient, baseURL, groupPayload)
			if err != nil {
				return fmt.Errorf("create group %s: %w", groupName, err)
			}
			if status != http.StatusOK {
				return fmt.Errorf("create group %s: HTTP %d", groupName, status)
			}
			time.Sleep(150 * time.Millisecond)

			if route.Enabled {
				routePayload := map[string]any{
					"dns-proxy": map[string]any{
						"route": []any{
							map[string]any{
								"group":     groupName,
								"interface": wgIface,
								"auto":      true,
							},
						},
					},
				}
				_, status, err := keeneticRciPost(httpClient, baseURL, routePayload)
				if err != nil {
					return fmt.Errorf("create route for %s: %w", groupName, err)
				}
				if status != http.StatusOK {
					return fmt.Errorf("create route for %s: HTTP %d", groupName, status)
				}
				time.Sleep(150 * time.Millisecond)
			}
		}
	}
	return nil
}

func (s *Server) listDnsRoutes(w http.ResponseWriter, r *http.Request) {
	peersCfg, _ := loadPeers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peersCfg.DnsRoutes)
}

func (s *Server) createDnsRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
		Subnets []string `json:"subnets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	peersCfg, _ := loadPeers()
	route := DnsRoute{
		ID:      generateID(),
		Name:    req.Name,
		Domains: req.Domains,
		Subnets: req.Subnets,
		Enabled: true,
	}
	peersCfg.DnsRoutes = append(peersCfg.DnsRoutes, route)
	_ = savePeers(peersCfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (s *Server) updateDnsRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
		Subnets []string `json:"subnets"`
		Enabled bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	peersCfg, _ := loadPeers()
	for i := range peersCfg.DnsRoutes {
		if peersCfg.DnsRoutes[i].ID == req.ID {
			peersCfg.DnsRoutes[i].Name = req.Name
			peersCfg.DnsRoutes[i].Domains = req.Domains
			peersCfg.DnsRoutes[i].Subnets = req.Subnets
			peersCfg.DnsRoutes[i].Enabled = req.Enabled
			_ = savePeers(peersCfg)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(peersCfg.DnsRoutes[i])
			return
		}
	}
	http.Error(w, "route not found", http.StatusNotFound)
}

func (s *Server) deleteDnsRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	peersCfg, _ := loadPeers()
	filtered := peersCfg.DnsRoutes[:0]
	for _, r := range peersCfg.DnsRoutes {
		if r.ID != req.ID {
			filtered = append(filtered, r)
		}
	}
	peersCfg.DnsRoutes = filtered
	_ = savePeers(peersCfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) applyDnsRoutesToRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
	}

	peersCfg, _ := loadPeers()
	if len(peersCfg.DnsRoutes) == 0 {
		http.Error(w, "no dns routes configured", http.StatusBadRequest)
		return
	}

	type applyResult struct {
		Peer   string   `json:"peer"`
		Router string   `json:"router"`
		Error  string   `json:"error,omitempty"`
		Routes []string `json:"routes,omitempty"`
	}
	var results []applyResult

	peers := peersCfg.Peers
	if req.PeerID != "" {
		for _, p := range peersCfg.Peers {
			if p.ID == req.PeerID {
				peers = []Peer{p}
				break
			}
		}
		if len(peers) == 0 {
			http.Error(w, "peer not found", http.StatusNotFound)
			return
		}
	}

	for _, peer := range peers {
		if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
			results = append(results, applyResult{
				Peer:   peer.Name,
				Router: peer.RouterDomain,
				Error:  "router credentials not configured",
			})
			continue
		}

		httpClient, baseURL, err := keeneticSetupClient(peer.RouterDomain, peer.RouterLogin, peer.RouterPassword)
		if err != nil {
			log.Printf("dns-routes apply auth failed for %s: %v", peer.Name, err)
			results = append(results, applyResult{
				Peer:   peer.Name,
				Router: peer.RouterDomain,
				Error:  fmt.Sprintf("auth failed: %v", err),
			})
			continue
		}

		wgIface := peer.RouterIfName
		if wgIface == "" {
			wgIface = "Wireguard1"
		}

		var applyPayload []routeApply
		var routeNames []string
		for _, rt := range peersCfg.DnsRoutes {
			applyPayload = append(applyPayload, routeApply{
				Name:    rt.Name,
				Domains: rt.Domains,
				Subnets: rt.Subnets,
				Enabled: rt.Enabled,
			})
			routeNames = append(routeNames, rt.Name)
		}

		if len(applyPayload) > 0 {
			if err := keeneticApplyDnsRoutes(httpClient, baseURL, wgIface, applyPayload); err != nil {
				log.Printf("dns-routes apply failed for %s: %v", peer.Name, err)
				results = append(results, applyResult{
					Peer:   peer.Name,
					Router: peer.RouterDomain,
					Error:  err.Error(),
					Routes: routeNames,
				})
				continue
			}
		}

		if err := keeneticSave(httpClient, baseURL); err != nil {
			log.Printf("dns-routes save failed for %s: %v", peer.Name, err)
			results = append(results, applyResult{
				Peer:   peer.Name,
				Router: peer.RouterDomain,
				Error:  fmt.Sprintf("save failed: %v", err),
				Routes: routeNames,
			})
			continue
		}

		results = append(results, applyResult{
			Peer:   peer.Name,
			Router: peer.RouterDomain,
			Routes: routeNames,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
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

	peersCfg, _ := loadPeers()
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
		log.Printf("keenetic dns-routes auth failed for %s: %v", peer.Name, err)
		http.Error(w, fmt.Sprintf("router auth failed: %v", err), http.StatusBadGateway)
		return
	}

	wanIface := "FastEthernet0/Vlan1"
	if err := keeneticSetDnsRoutes(httpClient, baseURL, wanIface, req.Enabled); err != nil {
		log.Printf("keenetic set dns-routes failed: %v", err)
		http.Error(w, fmt.Sprintf("set dns-routes failed: %v", err), http.StatusBadGateway)
		return
	}

	if err := keeneticSave(httpClient, baseURL); err != nil {
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

func (s *Server) getDnsRoutePresets(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("presets/dns-routes.json")
	if err != nil {
		http.Error(w, "presets not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

