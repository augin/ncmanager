package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareClient — минимальный клиент Cloudflare API v4 для управления
// DNS-записями (A и TXT), необходимыми для выпуска сертификата по DNS-01.
type cloudflareClient struct {
	token string
	http  *http.Client
}

func newCloudflareClient(token string) *cloudflareClient {
	return &cloudflareClient{
		token: strings.TrimSpace(token),
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

type cfAPIErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e cfAPIErr) Error() string {
	return fmt.Sprintf("Cloudflare API (код %d): %s", e.Code, e.Message)
}

// cfDNSRecord — DNS-запись Cloudflare.
type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// do выполняет запрос к Cloudflare API и декодирует result в out.
func (c *cloudflareClient) do(ctx context.Context, method, path string, body, out interface{}) error {
	if c.token == "" {
		return fmt.Errorf("Cloudflare: API-ключ не задан")
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPIBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Cloudflare: чтение ответа: %w", err)
	}
	var env struct {
		Success bool            `json:"success"`
		Errors  []cfAPIErr      `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("Cloudflare: неожиданный ответ (HTTP %d): %s", resp.StatusCode, truncateForLog(string(data)))
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return env.Errors[0]
		}
		return fmt.Errorf("Cloudflare: запрос не выполнен (HTTP %d)", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("Cloudflare: разбор результата: %w", err)
		}
	}
	return nil
}

// zoneCandidates возвращает кандидатов на зону Cloudflare для домена,
// от самого специфичного к более общему: sub.example.com →
// ["sub.example.com", "example.com"].
func zoneCandidates(domain string) []string {
	parts := strings.Split(strings.Trim(strings.ToLower(domain), "."), ".")
	var out []string
	for i := 0; i+2 <= len(parts); i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// findZone находит зону Cloudflare, которой принадлежит домен.
func (c *cloudflareClient) findZone(ctx context.Context, domain string) (id, name string, err error) {
	for _, cand := range zoneCandidates(domain) {
		var zones []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		q := "/zones?name=" + url.QueryEscape(cand)
		if err := c.do(ctx, http.MethodGet, q, nil, &zones); err != nil {
			return "", "", err
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, cand) && z.Status != "pending" {
				return z.ID, z.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("Cloudflare: зона для домена %s не найдена (проверьте, что домен добавлен в аккаунт)", domain)
}

// resolveZone возвращает зону: явно заданную в настройках или найденную
// автоматически по домену.
func (c *cloudflareClient) resolveZone(ctx context.Context, domain, explicitZone string) (id, name string, err error) {
	if z := strings.TrimSpace(explicitZone); z != "" {
		id, name, err = c.findZone(ctx, z)
		if err != nil {
			return "", "", err
		}
		if !dnsNameMatches(name, domain) {
			return "", "", fmt.Errorf("Cloudflare: домен %s не принадлежит зоне %s", domain, name)
		}
		return id, name, nil
	}
	return c.findZone(ctx, domain)
}

// dnsNameMatches проверяет, что name равен zone или является её поддоменом.
func dnsNameMatches(name, zone string) bool {
	name = strings.ToLower(strings.Trim(name, "."))
	zone = strings.ToLower(strings.Trim(zone, "."))
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// upsertARecord создаёт или обновляет A-запись name → ip. Возвращает
// "created", "updated" или "ok" (запись уже актуальна).
func (c *cloudflareClient) upsertARecord(ctx context.Context, zoneID, name, ip string) (string, error) {
	name = strings.ToLower(strings.Trim(name, "."))
	var records []cfDNSRecord
	q := fmt.Sprintf("/zones/%s/dns_records?type=A&name=%s", zoneID, url.QueryEscape(name))
	if err := c.do(ctx, http.MethodGet, q, nil, &records); err != nil {
		return "", err
	}
	if len(records) > 0 {
		rec := records[0]
		if rec.Content == ip {
			return "ok", nil
		}
		body := map[string]interface{}{"content": ip, "ttl": rec.TTL}
		path := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, rec.ID)
		if err := c.do(ctx, http.MethodPatch, path, body, nil); err != nil {
			return "", err
		}
		return "updated", nil
	}
	body := cfDNSRecord{Type: "A", Name: name, Content: ip, TTL: 1, Proxied: false}
	path := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	if err := c.do(ctx, http.MethodPost, path, body, nil); err != nil {
		return "", err
	}
	return "created", nil
}

// listRecordIDs возвращает ID DNS-записей заданного типа и имени.
func (c *cloudflareClient) listRecordIDs(ctx context.Context, zoneID, recType, name string) ([]string, error) {
	var records []cfDNSRecord
	q := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recType, url.QueryEscape(strings.ToLower(strings.Trim(name, "."))))
	if err := c.do(ctx, http.MethodGet, q, nil, &records); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(records))
	for _, rec := range records {
		ids = append(ids, rec.ID)
	}
	return ids, nil
}

// createTXTRecord создаёт TXT-запись, предварительно удаляя старые записи
// с тем же именем (остатки от прерванных выпусков). Возвращает ID записи.
func (c *cloudflareClient) createTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	ids, err := c.listRecordIDs(ctx, zoneID, "TXT", name)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		if err := c.deleteRecord(ctx, zoneID, id); err != nil {
			return "", err
		}
	}
	body := cfDNSRecord{Type: "TXT", Name: strings.ToLower(strings.Trim(name, ".")), Content: content, TTL: 120}
	path := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	if err := c.do(ctx, http.MethodPost, path, body, nil); err != nil {
		return "", err
	}
	// POST не возвращает запись в result, перечисляем для получения ID.
	ids, err = c.listRecordIDs(ctx, zoneID, "TXT", name)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("Cloudflare: TXT-запись %s не создана", name)
	}
	return ids[0], nil
}

// deleteRecord удаляет DNS-запись по ID.
func (c *cloudflareClient) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	path := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// truncateForLog обрезает длинный текст для вывода в лог.
func truncateForLog(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
