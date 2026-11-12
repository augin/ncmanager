package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var dnsApplyRunning atomic.Bool

type DnsRoute struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	Subnets  []string `json:"subnets,omitempty"`
	Enabled  bool     `json:"enabled"`
	Color    string   `json:"color,omitempty"`
	TunnelID string   `json:"tunnelId,omitempty"`
}

var cyrTranslitSlug = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "yo",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "sch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

var dnsGroupRe = regexp.MustCompile(`^.+_NCM\d+$`)

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

type routeApply struct {
	Name    string
	Domains []string
	Subnets []string
	Enabled bool
}

// dnsRouteChunkSize — максимальное число элементов в одной fqdn-группе.
const dnsRouteChunkSize = 300

// plannedGroup — ожидаемая fqdn-группа маршрута на роутере.
type plannedGroup struct {
	Name  string
	Items []string
}

// planRouteGroups разбивает элементы маршрута на группы <slug>_NCM<n>.
// Единый источник истины для применения и последующей проверки.
func planRouteGroups(route routeApply) []plannedGroup {
	items := make([]string, 0, len(route.Domains)+len(route.Subnets))
	items = append(items, route.Domains...)
	items = append(items, route.Subnets...)
	if len(items) == 0 {
		return nil
	}
	slug := sanitizeGroupSlug(route.Name)
	if slug == "" {
		slug = "route"
	}
	var out []plannedGroup
	for i := 0; i < len(items); i += dnsRouteChunkSize {
		end := i + dnsRouteChunkSize
		if end > len(items) {
			end = len(items)
		}
		out = append(out, plannedGroup{
			Name:  fmt.Sprintf("%s_NCM%d", slug, len(out)+1),
			Items: items[i:end],
		})
	}
	return out
}

func keeneticApplyDnsRoutes(httpClient *http.Client, baseURL, wgIface string, routes []routeApply, logFn func(string)) error {
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
		if !dnsGroupRe.MatchString(g) {
			continue
		}
		slug := g
		if idx := strings.LastIndex(g, "_NCM"); idx > 0 {
			slug = g[:idx]
		}
		if !activeSlugs[slug] {
			log.Printf("cleaning orphaned group: %s (slug=%s)", g, slug)
			if logFn != nil {
				logFn("🗑️ Удаление устаревшей группы: " + g + "\n")
			}
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
			time.Sleep(50 * time.Millisecond)

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
			time.Sleep(30 * time.Millisecond)
		}
	}

	for _, route := range routes {
		slug := sanitizeGroupSlug(route.Name)
		if slug == "" {
			slug = "route"
		}

		oldNames := make([]string, 0)
		for _, g := range existingGroups {
			if dnsGroupRe.MatchString(g) && strings.HasPrefix(g, slug+"_NCM") {
				oldNames = append(oldNames, g)
			}
		}

		if len(oldNames) > 0 {
			if logFn != nil {
				logFn("🗑️ Удаление старых списков для: " + route.Name + " (" + strings.Join(oldNames, ", ") + ")\n")
			}
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
				log.Printf("delete old groups for %s: %v (skipping)", route.Name, err)
			}
			if status != http.StatusOK {
				log.Printf("RCI delete old groups for %s: HTTP %d", route.Name, status)
			}
			time.Sleep(50 * time.Millisecond)

			for _, n := range oldNames {
				delRoutePayload := map[string]any{
					"dns-proxy": map[string]any{
						"route": []any{map[string]any{"group": n, "interface": wgIface, "no": true}},
					},
				}
				_, status, err := keeneticRciPost(httpClient, baseURL, delRoutePayload)
				if err != nil {
					log.Printf("delete old route %s: %v (skipping)", n, err)
				}
				if status != http.StatusOK {
					log.Printf("RCI delete old route %s: HTTP %d", n, status)
				}
				time.Sleep(30 * time.Millisecond)
			}
		}

		groups := planRouteGroups(route)
		if len(groups) == 0 {
			if logFn != nil {
				logFn("⏭️ Маршрут пустой, пропуск: " + route.Name + "\n")
			}
			continue
		}

		for _, group := range groups {
			groupName := group.Name
			chunk := group.Items

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
				log.Printf("create group %s: %v (skipping)", groupName, err)
			}
			if status != http.StatusOK {
				log.Printf("create group %s: HTTP %d (skipping)", groupName, status)
			}
			if logFn != nil {
				logFn("📋 Создан список: " + groupName + " (" + strconv.Itoa(len(chunk)) + " элементов)\n")
			}
			time.Sleep(50 * time.Millisecond)

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
					log.Printf("create route for %s: %v (skipping)", groupName, err)
				}
				if status != http.StatusOK {
					log.Printf("create route for %s: HTTP %d (skipping)", groupName, status)
				}
				if logFn != nil {
					logFn("  ➜ Маршрут: " + groupName + " → " + wgIface + "\n")
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
	return nil
}

// includeAddrs разбирает значение "include" из дампа роутера:
// список адресов, одиночный адрес или объект {"address": ...}.
func includeAddrs(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case []any:
		for _, e := range t {
			out = append(out, includeAddrs(e)...)
		}
	case map[string]any:
		if addr, ok := t["address"]; ok {
			out = append(out, includeAddrs(addr)...)
		}
	}
	return out
}

// parseFqdnGroups разбирает секцию object-group дампа роутера:
// имя fqdn-группы -> адреса из include.
func parseFqdnGroups(og any) map[string][]string {
	groups := make(map[string][]string)
	ogMap, ok := og.(map[string]any)
	if !ok {
		return groups
	}
	fqdn, ok := ogMap["fqdn"].(map[string]any)
	if !ok {
		return groups
	}
	for name, def := range fqdn {
		defMap, ok := def.(map[string]any)
		if !ok {
			continue
		}
		if inc, ok := defMap["include"]; ok {
			groups[name] = includeAddrs(inc)
		}
	}
	return groups
}

// parseDnsProxyRoutes разбирает секцию dns-proxy.route дампа роутера:
// имя группы -> множество интерфейсов, на которые ведут маршруты.
func parseDnsProxyRoutes(dp any) map[string]map[string]bool {
	routes := make(map[string]map[string]bool)
	add := func(group, iface string) {
		if group == "" {
			return
		}
		if routes[group] == nil {
			routes[group] = make(map[string]bool)
		}
		routes[group][iface] = true
	}
	entry := func(e any) {
		m, ok := e.(map[string]any)
		if !ok {
			return
		}
		group, _ := m["group"].(string)
		iface, _ := m["interface"].(string)
		add(group, iface)
	}
	dpMap, ok := dp.(map[string]any)
	if !ok {
		return routes
	}
	switch t := dpMap["route"].(type) {
	case []any:
		for _, e := range t {
			entry(e)
		}
	case map[string]any:
		if _, has := t["group"]; has {
			entry(t)
		} else {
			for _, e := range t {
				entry(e)
			}
		}
	}
	return routes
}

// keeneticGetDnsState читает из конфигурации роутера fqdn-группы
// (имя -> адреса) и маршруты dns-proxy (группа -> интерфейсы).
func keeneticGetDnsState(httpClient *http.Client, baseURL string) (map[string][]string, map[string]map[string]bool, error) {
	resp, err := keeneticGetWithTimeout(httpClient, baseURL+"/rci/", keeneticRciDumpTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("get rci dump failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, nil, fmt.Errorf("parse rci dump failed: %v", err)
	}
	return parseFqdnGroups(parsed["object-group"]), parseDnsProxyRoutes(parsed["dns-proxy"]), nil
}

// verifyDnsRoutesState сравнивает ожидаемые группы и маршруты с
// фактическим состоянием роутера. Пустой список проблем = все маршруты
// успешно добавлены.
func verifyDnsRoutesState(wgIface string, routes []routeApply, actualGroups map[string][]string, actualRoutes map[string]map[string]bool) []string {
	var problems []string
	for _, route := range routes {
		for _, g := range planRouteGroups(route) {
			items, ok := actualGroups[g.Name]
			if !ok {
				problems = append(problems, fmt.Sprintf("маршрут «%s»: группа %s не найдена на роутере", route.Name, g.Name))
				continue
			}
			have := make(map[string]bool, len(items))
			for _, it := range items {
				have[it] = true
			}
			var missing []string
			for _, it := range g.Items {
				if !have[it] {
					missing = append(missing, it)
				}
			}
			if len(missing) > 0 {
				problems = append(problems, fmt.Sprintf("маршрут «%s»: в группе %s отсутствует %d из %d элементов: %s",
					route.Name, g.Name, len(missing), len(g.Items), formatItemList(missing, 5)))
			}
			ifaces := actualRoutes[g.Name]
			if route.Enabled {
				switch {
				case ifaces == nil:
					problems = append(problems, fmt.Sprintf("маршрут «%s»: dns-proxy маршрут %s → %s не найден", route.Name, g.Name, wgIface))
				case !ifaces[wgIface]:
					problems = append(problems, fmt.Sprintf("маршрут «%s»: %s ведёт на %s вместо %s", route.Name, g.Name, formatItemList(mapKeys(ifaces), 3), wgIface))
				}
			} else if ifaces != nil {
				problems = append(problems, fmt.Sprintf("маршрут «%s»: отключён, но dns-proxy маршрут %s всё ещё существует", route.Name, g.Name))
			}
		}
	}
	return problems
}

// keeneticVerifyDnsRoutes проверяет на роутере, что все маршруты
// действительно добавлены. Возвращает список проблем.
func keeneticVerifyDnsRoutes(httpClient *http.Client, baseURL, wgIface string, routes []routeApply) ([]string, error) {
	groups, dnsRoutes, err := keeneticGetDnsState(httpClient, baseURL)
	if err != nil {
		return nil, err
	}
	return verifyDnsRoutesState(wgIface, routes, groups, dnsRoutes), nil
}

// dnsRoutesTotals считает ожидаемое число групп и элементов.
func dnsRoutesTotals(routes []routeApply) (groups, items int) {
	for _, route := range routes {
		for _, g := range planRouteGroups(route) {
			groups++
			items += len(g.Items)
		}
	}
	return groups, items
}

// formatItemList выводит до limit элементов через запятую.
func formatItemList(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s и ещё %d", strings.Join(items[:limit], ", "), len(items)-limit)
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (s *Server) listDnsRoutes(w http.ResponseWriter, r *http.Request) {
	routes, _ := loadDnsRoutes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
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
	routes, _ := loadDnsRoutes()
	route := DnsRoute{
		ID:      generateID(),
		Name:    req.Name,
		Domains: req.Domains,
		Subnets: req.Subnets,
		Enabled: true,
	}
	routes = append(routes, route)
	_ = saveDnsRoutes(routes)
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
	routes, _ := loadDnsRoutes()
	for i := range routes {
		if routes[i].ID == req.ID {
			routes[i].Name = req.Name
			routes[i].Domains = req.Domains
			routes[i].Subnets = req.Subnets
			routes[i].Enabled = req.Enabled
			_ = saveDnsRoutes(routes)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(routes[i])
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
	routes, _ := loadDnsRoutes()
	filtered := routes[:0]
	for _, r := range routes {
		if r.ID != req.ID {
			filtered = append(filtered, r)
		}
	}
	_ = saveDnsRoutes(filtered)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) applyDnsRoutesToRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !dnsApplyRunning.CompareAndSwap(false, true) {
		http.Error(w, "DNS routes apply already running", http.StatusTooManyRequests)
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			dnsApplyRunning.Store(false)
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
	}

	routes, _ := loadDnsRoutes()
	if len(routes) == 0 {
		dnsApplyRunning.Store(false)
		http.Error(w, "no dns routes configured", http.StatusBadRequest)
		return
	}

	os.WriteFile(filepath.Join(logDir, "dns-apply.status"), []byte("running"), 0644)
	os.WriteFile(filepath.Join(logDir, "dns-apply.log"), []byte("Запуск применения DNS маршрутов...\n"), 0644)

	go func() {
		type applyResult struct {
			Peer     string   `json:"peer"`
			Router   string   `json:"router"`
			Error    string   `json:"error,omitempty"`
			Routes   []string `json:"routes,omitempty"`
			Problems []string `json:"problems,omitempty"`
		}
		var results []applyResult
		var hadErrors bool
		peersCfg, _ := loadPeers()
		peers := peersCfg.Peers
		if req.PeerID != "" {
			for _, p := range peersCfg.Peers {
				if p.ID == req.PeerID {
					peers = []Peer{p}
					break
				}
			}
		}

		for _, peer := range peers {
			if peer.RouterDomain == "" || peer.RouterLogin == "" || peer.RouterPassword == "" {
				hadErrors = true
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
				hadErrors = true
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
			for _, rt := range routes {
				applyPayload = append(applyPayload, routeApply{
					Name:    rt.Name,
					Domains: rt.Domains,
					Subnets: rt.Subnets,
					Enabled: rt.Enabled,
				})
				routeNames = append(routeNames, rt.Name)
			}

			if len(applyPayload) > 0 {
				appendLog(fmt.Sprintf("📡 Применение %d маршрутов на %s (%s)...\n", len(applyPayload), peer.Name, peer.RouterDomain))
				if err := keeneticApplyDnsRoutes(httpClient, baseURL, wgIface, applyPayload, appendLog); err != nil {
					log.Printf("dns-routes apply failed for %s: %v", peer.Name, err)
					appendLog(fmt.Sprintf("❌ Ошибка применения на %s: %v\n", peer.Name, err))
					hadErrors = true
					results = append(results, applyResult{
						Peer:   peer.Name,
						Router: peer.RouterDomain,
						Error:  err.Error(),
						Routes: routeNames,
					})
					continue
				}
				appendLog(fmt.Sprintf("✅ Маршруты применены на %s\n", peer.Name))
			}

			if err := keeneticSave(httpClient, baseURL); err != nil {
				log.Printf("dns-routes save failed for %s: %v", peer.Name, err)
				appendLog(fmt.Sprintf("❌ Ошибка сохранения на %s: %v\n", peer.Name, err))
				hadErrors = true
				results = append(results, applyResult{
					Peer:   peer.Name,
					Router: peer.RouterDomain,
					Error:  fmt.Sprintf("save failed: %v", err),
					Routes: routeNames,
				})
				continue
			}

			appendLog(fmt.Sprintf("✅ Конфигурация сохранена на %s\n", peer.Name))

			// Проверка: все ли маршруты действительно добавились на роутер.
			if len(applyPayload) > 0 {
				appendLog(fmt.Sprintf("🔎 Проверка маршрутов на %s...\n", peer.Name))
				problems, verr := keeneticVerifyDnsRoutes(httpClient, baseURL, wgIface, applyPayload)
				if verr != nil {
					log.Printf("dns-routes verify failed for %s: %v", peer.Name, verr)
					appendLog(fmt.Sprintf("⚠️ Проверка не выполнена: %v\n", verr))
					hadErrors = true
					results = append(results, applyResult{
						Peer:   peer.Name,
						Router: peer.RouterDomain,
						Error:  fmt.Sprintf("verify failed: %v", verr),
						Routes: routeNames,
					})
					continue
				}
				if len(problems) > 0 {
					for _, p := range problems {
						appendLog("  ⚠️ " + p + "\n")
					}
					appendLog(fmt.Sprintf("❌ Проверка: обнаружено проблем — %d\n", len(problems)))
					hadErrors = true
					results = append(results, applyResult{
						Peer:     peer.Name,
						Router:   peer.RouterDomain,
						Error:    fmt.Sprintf("проверка: %d проблем", len(problems)),
						Routes:   routeNames,
						Problems: problems,
					})
					continue
				}
				groups, items := dnsRoutesTotals(applyPayload)
				appendLog(fmt.Sprintf("✅ Проверка: все маршруты добавлены (%d групп, %d элементов)\n", groups, items))
			}

			results = append(results, applyResult{
				Peer:   peer.Name,
				Router: peer.RouterDomain,
				Routes: routeNames,
			})
		}

		status := "completed"
		finalMsg := "\n🎉 Готово!\n"
		if hadErrors {
			status = "failed"
			finalMsg = "\n⚠️ Завершено с ошибками, см. лог выше\n"
		}
		if data, err := json.MarshalIndent(results, "", "  "); err == nil {
			os.WriteFile(filepath.Join(logDir, "dns-apply.result.json"), data, 0644)
		}
		os.WriteFile(filepath.Join(logDir, "dns-apply.status"), []byte(status), 0644)
		appendLog(finalMsg)
		dnsApplyRunning.Store(false)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func appendLog(msg string) {
	f, err := os.OpenFile(filepath.Join(logDir, "dns-apply.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg)
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
	peerIdx := findPeerIndex(peersCfg.Peers, id)
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
		"status":   "ok",
		"enabled":  req.Enabled,
		"wanIface": wanIface,
		"peer":     peer.Name,
	})
}

func (s *Server) getDnsRoutePresets(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(presetsFile)
	if err != nil {
		http.Error(w, "presets not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) exportDnsRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	routes, err := loadDnsRoutes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(routes, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"dns-routes.json\"")
	w.Write(data)
}

func (s *Server) importDnsRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid multipart: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read file failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	var routes []DnsRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if routes == nil {
		routes = []DnsRoute{}
	}
	if err := saveDnsRoutes(routes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"count": len(routes)})
}
