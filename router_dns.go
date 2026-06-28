package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func keeneticAddDnsTls(httpClient *http.Client, baseURL, address, sni, domain string) error {
	upstream := map[string]any{"address": address}
	if sni != "" {
		upstream["sni"] = sni
	}
	if domain != "" {
		upstream["domain"] = domain
	}
	payload := map[string]any{
		"dns-proxy": map[string]any{
			"tls": map[string]any{
				"upstream": []any{upstream},
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
	for _, srv := range dnsServers {
		if err := keeneticAddDnsTls(httpClient, baseURL, srv.address, srv.sni, srv.domain); err != nil {
			log.Printf("keenetic add dns tls %s failed: %v", srv.address, err)
		}
	}
	return nil
}
