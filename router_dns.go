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

	// Collect unique addresses to delete first
	addressesToDelete := make(map[string]bool)
	for _, srv := range dnsServers {
		addressesToDelete[srv.address] = true
	}

	// Delete existing entries for each address (removes all variants: plain/domain/fqdn)
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

	// Now add fresh upstreams
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
