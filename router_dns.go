package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

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
