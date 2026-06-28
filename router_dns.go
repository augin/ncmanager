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
	}{
		{"9.9.9.9", "dns.quad9.net"},
		{"1.1.1.1", "cloudflare-dns.com"},
		{"common.dot.dns.yandex.net", "ru"},
		{"common.dot.dns.yandex.net", "su"},
		{"common.dot.dns.yandex.net", "xn--p1ai"},
	}

	var upstreams []any
	for _, srv := range dnsServers {
		upstream := map[string]any{"address": srv.address}
		if srv.sni != "" {
			upstream["fqdn"] = srv.sni
		}
		upstreams = append(upstreams, upstream)
	}

	// First clear existing TLS upstreams to avoid duplicates
	clearPayload := map[string]any{
		"dns-proxy": map[string]any{
			"tls": map[string]any{
				"upstream": []any{},
			},
		},
	}
	_, clearStatus, clearErr := keeneticRciPost(httpClient, baseURL, clearPayload)
	if clearErr != nil {
		return fmt.Errorf("clear dns tls failed: %w", clearErr)
	}
	if clearStatus != http.StatusOK {
		return fmt.Errorf("clear dns tls failed (HTTP %d)", clearStatus)
	}
	time.Sleep(200 * time.Millisecond)

	// Now set the new upstreams
	payload := map[string]any{
		"dns-proxy": map[string]any{
			"tls": map[string]any{
				"upstream": upstreams,
			},
		},
	}
	_, setStatus, setErr := keeneticRciPost(httpClient, baseURL, payload)
	if setErr != nil {
		return setErr
	}
	if setStatus != http.StatusOK {
		return fmt.Errorf("add dns tls failed (HTTP %d)", setStatus)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}
