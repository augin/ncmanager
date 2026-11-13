package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestZoneCandidates(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"nas.example.com", []string{"nas.example.com", "example.com"}},
		{"example.com", []string{"example.com"}},
		{"a.b.example.co.uk", []string{"a.b.example.co.uk", "b.example.co.uk", "example.co.uk", "co.uk"}},
		{"Example.COM.", []string{"example.com"}},
	}
	for _, tt := range tests {
		got := zoneCandidates(tt.domain)
		if len(got) != len(tt.want) {
			t.Errorf("zoneCandidates(%q) = %v, want %v", tt.domain, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("zoneCandidates(%q)[%d] = %q, want %q", tt.domain, i, got[i], tt.want[i])
			}
		}
	}
}

func TestDNSNameMatches(t *testing.T) {
	tests := []struct {
		name, zone string
		want       bool
	}{
		{"nas.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"a.b.example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.evil.net", "example.com", false},
		{"NAS.Example.COM.", "example.com", true},
	}
	for _, tt := range tests {
		if got := dnsNameMatches(tt.name, tt.zone); got != tt.want {
			t.Errorf("dnsNameMatches(%q, %q) = %v, want %v", tt.name, tt.zone, got, tt.want)
		}
	}
}

func TestNormalizeTLSProvider(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"cloudflare", tlsProviderCloudflare},
		{" Cloudflare ", tlsProviderCloudflare},
		{"http-01", tlsProviderHTTP01},
		{"", tlsProviderHTTP01},
		{"unknown", tlsProviderHTTP01},
	}
	for _, tt := range tests {
		if got := normalizeTLSProvider(tt.in); got != tt.want {
			t.Errorf("normalizeTLSProvider(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadOrCreateECKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key.pem"

	key1, err := loadOrCreateECKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateECKey: %v", err)
	}
	key2, err := loadOrCreateECKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateECKey (повторно): %v", err)
	}
	if !key1.Equal(key2) {
		t.Error("повторная загрузка вернула другой ключ")
	}
}

func TestCertPaths(t *testing.T) {
	certFile, keyFile := certPaths("data/tls-cache", "nas.example.com")
	if certFile != "data/tls-cache/nas.example.com.crt" {
		t.Errorf("certFile = %q", certFile)
	}
	if keyFile != "data/tls-cache/nas.example.com.key" {
		t.Errorf("keyFile = %q", keyFile)
	}
	if got := certKeyPath("data/tls-cache", "nas.example.com"); got != keyFile {
		t.Errorf("certKeyPath = %q, want %q", got, keyFile)
	}
}

func TestTLSCacheDirDefault(t *testing.T) {
	dir := tlsCacheDir(&Config{})
	if dir != "data/tls-cache" {
		t.Errorf("tlsCacheDir по умолчанию = %q", dir)
	}
	if dir := tlsCacheDir(&Config{TLSCache: "data/custom-cache"}); dir != "data/custom-cache" {
		t.Errorf("tlsCacheDir из конфига = %q", dir)
	}
}

func TestApplyTLSRequestFields(t *testing.T) {
	cfg := &Config{}
	req := map[string]any{
		"tlsEnabled":      true,
		"tlsHost":         " nas.example.com ",
		"tlsCache":        " data/tls-cache ",
		"tlsPort":         float64(8443),
		"tlsProvider":     "cloudflare",
		"cloudflareToken": " token-123 ",
		"cloudflareZone":  "example.com",
	}
	if err := applyTLSRequestFields(req, cfg); err != nil {
		t.Fatalf("applyTLSRequestFields: %v", err)
	}
	if !cfg.TLSEnabled || cfg.TLSHost != "nas.example.com" || cfg.TLSPort != 8443 ||
		cfg.TLSProvider != "cloudflare" || cfg.CloudflareToken != "token-123" ||
		cfg.CloudflareZone != "example.com" || cfg.TLSCache != "data/tls-cache" {
		t.Errorf("поля разобраны неверно: %+v", cfg)
	}

	// Некорректный порт — ошибка
	if err := applyTLSRequestFields(map[string]any{"tlsPort": float64(70000)}, cfg); err == nil {
		t.Error("ожидалась ошибка для tlsPort=70000")
	}
}

// TestChallengeName проверяет имя TXT-записи для wildcard-домена.
func TestChallengeName(t *testing.T) {
	tests := []struct {
		identifier string
		want       string
	}{
		{"nas.example.com", "_acme-challenge.nas.example.com"},
		{"*.example.com", "_acme-challenge.example.com"},
		{"NAS.Example.COM.", "_acme-challenge.nas.example.com"},
	}
	for _, tt := range tests {
		if got := challengeTXTName(tt.identifier); got != tt.want {
			t.Errorf("имя TXT-записи для %q = %q, want %q", tt.identifier, got, tt.want)
		}
	}
}

func TestHTTPSStateSnapshot(t *testing.T) {
	// Проверка, что статус HTTPS формируется без конфигурации.
	st := (&httpsManager{}).snapshot()
	if st.Running || st.Enabled {
		t.Errorf("пустой менеджер не должен быть запущен: %+v", st)
	}
}

// TestLoadCachedCertRoundtrip проверяет сохранение и загрузку сертификата.
func TestLoadCachedCertRoundtrip(t *testing.T) {
	dir := t.TempDir()
	host := "nas.example.com"
	notAfter := time.Now().Add(24 * time.Hour)

	key, err := loadOrCreateECKey(certKeyPath(dir, host))
	if err != nil {
		t.Fatalf("loadOrCreateECKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certFile, keyFile := certPaths(dir, host)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("запись сертификата: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("запись ключа: %v", err)
	}

	cert, until, err := (&httpsManager{}).loadCachedCert(dir, host)
	if err != nil {
		t.Fatalf("loadCachedCert: %v", err)
	}
	if cert == nil || cert.Leaf == nil || cert.Leaf.Subject.CommonName != host {
		t.Errorf("загруженный сертификат повреждён: %+v", cert)
	}
	if until.Before(notAfter.Add(-time.Minute)) || until.After(notAfter.Add(time.Minute)) {
		t.Errorf("срок действия = %s, want ~%s", until, notAfter)
	}

	// Истёкший сертификат должен отклоняться.
	expired := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	derExpired, err := x509.CreateCertificate(rand.Reader, expired, expired, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate (expired): %v", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derExpired}), 0644); err != nil {
		t.Fatalf("запись истёкшего сертификата: %v", err)
	}
	if _, _, err := (&httpsManager{}).loadCachedCert(dir, host); err == nil {
		t.Error("истёкший сертификат не должен загружаться")
	}
}
