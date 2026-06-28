package main

import (
	"fmt"
	"net/http"
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
		{"common.dot.dns.yandex.net", "", "ru"},
		{"common.dot.dns.yandex.net", "", "su"},
		{"common.dot.dns.yandex.net", "", "xn--p1ai"},
	}

	var upstreams []any
	for _, srv := range dnsServers {
		upstream := map[string]any{"address": srv.address}
		if srv.sni != "" {
			upstream["server-name"] = srv.sni
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
	time.Sleep(200 * time.Millisecond)
	return nil
}
