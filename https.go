package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Провайдеры выпуска сертификата (способ проверки домена).
const (
	tlsProviderHTTP01     = "http-01"    // проверка через порт 80 (autocert)
	tlsProviderCloudflare = "cloudflare" // DNS-01 через Cloudflare API
)

// tlsDefaultPort — порт HTTPS по умолчанию.
const tlsDefaultPort = 443

// tlsRenewBefore — за сколько дней до истечения перевыпускать сертификат.
const tlsRenewBefore = 30 * 24 * time.Hour

// certHolder хранит текущий сертификат так, чтобы обновление при
// перевыпуске не требовало перезапуска слушателя.
type certHolder struct {
	v atomic.Pointer[tls.Certificate]
}

func (h *certHolder) set(cert *tls.Certificate) { h.v.Store(cert) }
func (h *certHolder) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.v.Load()
	if cert == nil {
		return nil, fmt.Errorf("сертификат не выпущен")
	}
	return cert, nil
}

// httpsManager управляет HTTPS-слушателем и сертификатом.
type httpsManager struct {
	mu           sync.Mutex
	provisioning bool
	reapply      bool

	running  bool
	port     int
	host     string
	provider string
	server   *http.Server
	holder   certHolder
	autocert atomic.Pointer[autocert.Manager]

	dnsRecord string // состояние A-записи, например "created (A nas.example.com → 1.2.3.4)"
	certUntil time.Time
	message   string
	lastError string
	updatedAt time.Time
}

var httpsMgr = &httpsManager{}

// httpsState — состояние HTTPS для отображения в веб-интерфейсе.
type httpsState struct {
	Enabled      bool   `json:"enabled"`
	Running      bool   `json:"running"`
	Port         int    `json:"port"`
	Host         string `json:"host"`
	Provider     string `json:"provider"`
	Provisioning bool   `json:"provisioning"`
	DNSRecord    string `json:"dnsRecord"`
	CertExpiry   string `json:"certExpiry"`
	CertValid    bool   `json:"certValid"`
	Message      string `json:"message"`
	LastError    string `json:"lastError"`
	UpdatedAt    string `json:"updatedAt"`
}

// snapshot возвращает копию текущего состояния.
func (m *httpsManager) snapshot() httpsState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := httpsState{
		Running:      m.running,
		Port:         m.port,
		Host:         m.host,
		Provider:     m.provider,
		Provisioning: m.provisioning,
		DNSRecord:    m.dnsRecord,
		Message:      m.message,
		LastError:    m.lastError,
	}
	if !m.certUntil.IsZero() {
		st.CertExpiry = m.certUntil.Format(time.RFC3339)
		st.CertValid = time.Now().Before(m.certUntil)
	}
	if !m.updatedAt.IsZero() {
		st.UpdatedAt = m.updatedAt.Format(time.RFC3339)
	}
	return st
}

func (m *httpsManager) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastError = err.Error()
	m.updatedAt = time.Now()
	log.Printf("https: %v", err)
}

func (m *httpsManager) setOK(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastError = ""
	m.message = msg
	m.updatedAt = time.Now()
	log.Printf("https: %s", msg)
}

// initHTTPS запускает первичное применение настроек HTTPS и цикл
// продления сертификата. Порт 80 поднимается только для HTTP-01.
func initHTTPS() {
	startACMEResponder()
	go func() {
		applyTLSFromConfig()
		for range time.Tick(12 * time.Hour) {
			applyTLSFromConfig()
		}
	}()
}

// applyTLSFromConfig применяет настройки HTTPS из конфига: создаёт
// A-запись, выпускает/продлевает сертификат, поднимает или гасит
// слушатель. Повторный вызов во время работы будет выполнен после
// завершения текущего.
func applyTLSFromConfig() {
	httpsMgr.mu.Lock()
	if httpsMgr.provisioning {
		httpsMgr.reapply = true
		httpsMgr.mu.Unlock()
		return
	}
	httpsMgr.provisioning = true
	httpsMgr.mu.Unlock()

	for {
		httpsMgr.applyOnce()
		httpsMgr.mu.Lock()
		if !httpsMgr.reapply {
			httpsMgr.provisioning = false
			httpsMgr.mu.Unlock()
			return
		}
		httpsMgr.reapply = false
		httpsMgr.mu.Unlock()
	}
}

// applyOnce выполняет один проход применения настроек HTTPS.
func (m *httpsManager) applyOnce() {
	cfg, err := loadConfig(dataFile)
	if err != nil || cfg == nil {
		m.setErr(fmt.Errorf("не удалось загрузить конфигурацию: %v", err))
		return
	}
	host := strings.TrimSpace(cfg.TLSHost)
	provider := normalizeTLSProvider(cfg.TLSProvider)
	port := cfg.TLSPort
	if port == 0 {
		port = tlsDefaultPort
	}

	m.mu.Lock()
	m.host = host
	m.provider = provider
	m.port = port
	m.mu.Unlock()

	if !cfg.TLSEnabled {
		m.stopListener()
		m.setOK("HTTPS выключен")
		return
	}
	if host == "" {
		m.stopListener()
		m.setErr(fmt.Errorf("не указан домен (TLS Host)"))
		return
	}

	if provider == tlsProviderCloudflare {
		m.applyDNS01(cfg, host, port)
		return
	}
	m.applyHTTP01(cfg, host, port)
}

// applyDNS01: A-запись в Cloudflare + сертификат Let's Encrypt по DNS-01.
func (m *httpsManager) applyDNS01(cfg *Config, host string, port int) {
	token := strings.TrimSpace(cfg.CloudflareToken)
	if token == "" {
		m.setErr(fmt.Errorf("не задан API-ключ Cloudflare"))
		return
	}
	ip := getPublicIP()
	if net.ParseIP(ip) == nil {
		m.setErr(fmt.Errorf("не удалось определить публичный IP сервера"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cf := newCloudflareClient(token)
	zoneID, zoneName, err := cf.resolveZone(ctx, host, cfg.CloudflareZone)
	if err != nil {
		m.setErr(err)
		return
	}

	aName := baseDomainName(host)
	recState, err := cf.upsertARecord(ctx, zoneID, aName, ip)
	if err != nil {
		m.setErr(fmt.Errorf("A-запись: %w", err))
		return
	}
	m.mu.Lock()
	m.dnsRecord = fmt.Sprintf("%s (A %s → %s, зона %s)", recState, aName, ip, zoneName)
	m.mu.Unlock()

	cert, until, err := m.ensureCert(ctx, cfg, host, cf, zoneID)
	if err != nil {
		m.setErr(fmt.Errorf("сертификат: %w", err))
		return
	}
	m.holder.set(cert)
	m.mu.Lock()
	m.certUntil = until
	m.mu.Unlock()

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.holder.getCertificate,
	}
	if err := m.ensureListener(port, host, tlsProviderCloudflare, tlsCfg); err != nil {
		m.setErr(err)
		return
	}
	m.setOK(fmt.Sprintf("HTTPS работает на порту %d (%s)", port, host))
}

// applyHTTP01: прежний режим autocert — проверка через порт 80.
func (m *httpsManager) applyHTTP01(cfg *Config, host string, port int) {
	cacheDir := tlsCacheDir(cfg)
	_ = os.MkdirAll(cacheDir, 0700)
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
		Cache:      autocert.DirCache(cacheDir),
	}
	m.autocert.Store(mgr)

	cert, until, err := m.loadCachedCert(cacheDir, host)
	if err == nil {
		m.holder.set(cert)
		m.mu.Lock()
		m.certUntil = until
		m.mu.Unlock()
	}

	if err := m.ensureListener(port, host, tlsProviderHTTP01, mgr.TLSConfig()); err != nil {
		m.setErr(err)
		return
	}
	m.setOK(fmt.Sprintf("HTTPS работает на порту %d (%s, проверка http-01)", port, host))
}

// ensureCert возвращает сертификат из кэша (если действует больше 30 дней)
// или выпускает новый через ACME DNS-01.
func (m *httpsManager) ensureCert(ctx context.Context, cfg *Config, host string, cf *cloudflareClient, zoneID string) (*tls.Certificate, time.Time, error) {
	cacheDir := tlsCacheDir(cfg)
	_ = os.MkdirAll(cacheDir, 0700)
	cert, until, err := m.loadCachedCert(cacheDir, host)
	if err == nil && time.Until(until) > tlsRenewBefore {
		return cert, until, nil
	}
	if err != nil {
		log.Printf("https: сертификат в кэше не найден/недействителен (%v), выпускаем новый", err)
	} else {
		log.Printf("https: сертификат истекает %s, перевыпускаем", until.Format(time.RFC3339))
	}

	certPEM, keyPEM, until, err := issueCertDNS01(ctx, cacheDir, host, cf, zoneID)
	if err != nil {
		return nil, time.Time{}, err
	}
	certFile, keyFile := certPaths(cacheDir, host)
	if err := writeFileAtomic(certFile, certPEM); err != nil {
		return nil, time.Time{}, err
	}
	if err := writeFileAtomic(keyFile, keyPEM); err != nil {
		return nil, time.Time{}, err
	}
	_ = os.Chmod(keyFile, 0600)

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			pair.Leaf = leaf
			until = leaf.NotAfter
		}
	}
	return &pair, until, nil
}

// loadCachedCert загружает сертификат из кэша и возвращает срок его действия.
func (m *httpsManager) loadCachedCert(cacheDir, host string) (*tls.Certificate, time.Time, error) {
	certFile, keyFile := certPaths(cacheDir, host)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(pair.Certificate) == 0 {
		return nil, time.Time{}, fmt.Errorf("сертификат %s пуст", certFile)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, time.Time{}, fmt.Errorf("сертификат истёк %s", leaf.NotAfter.Format(time.RFC3339))
	}
	pair.Leaf = leaf
	return &pair, leaf.NotAfter, nil
}

// issueCertDNS01 выпускает сертификат Let's Encrypt для host, проверяя
// домен через TXT-запись _acme-challenge в Cloudflare.
func issueCertDNS01(ctx context.Context, cacheDir, host string, cf *cloudflareClient, zoneID string) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	accountKey, err := loadOrCreateECKey(filepath.Join(cacheDir, "acme-account.key"))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("ключ аккаунта ACME: %w", err)
	}
	certKey, err := loadOrCreateECKey(certKeyPath(cacheDir, host))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("ключ сертификата: %w", err)
	}

	client := &acme.Client{Key: accountKey, DirectoryURL: acme.LetsEncryptURL}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, nil, time.Time{}, fmt.Errorf("регистрация аккаунта ACME: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: host}})
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("создание заказа: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := solveDNS01(ctx, client, cf, zoneID, authzURL); err != nil {
			return nil, nil, time.Time{}, err
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("ожидание заказа: %w", err)
	}

	names := []string{host}
	if base := strings.TrimPrefix(host, "*."); base != host {
		names = append(names, base)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: strings.TrimPrefix(host, "*.")},
		DNSNames: names,
	}, certKey)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("создание CSR: %w", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("получение сертификата: %w", err)
	}
	if len(der) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("CA вернул пустой сертификат")
	}

	var certBuf strings.Builder
	for _, block := range der {
		if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: block}); err != nil {
			return nil, nil, time.Time{}, err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	var keyBuf strings.Builder
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, time.Time{}, err
	}

	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	log.Printf("https: сертификат %s выпущен до %s", host, leaf.NotAfter.Format(time.RFC3339))
	return []byte(certBuf.String()), []byte(keyBuf.String()), leaf.NotAfter, nil
}

// solveDNS01 проходит одну авторизацию ACME через TXT-запись в Cloudflare.
func solveDNS01(ctx context.Context, client *acme.Client, cf *cloudflareClient, zoneID, authzURL string) error {
	az, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("получение авторизации: %w", err)
	}
	if az.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, ch := range az.Challenges {
		if ch.Type == "dns-01" {
			chal = ch
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("CA не предложил проверку dns-01 для %s", az.Identifier.Value)
	}
	record, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	chalName := challengeTXTName(az.Identifier.Value)
	txtID, err := cf.createTXTRecord(ctx, zoneID, chalName, record)
	if err != nil {
		return fmt.Errorf("TXT-запись %s: %w", chalName, err)
	}
	defer func() {
		if delErr := cf.deleteRecord(context.Background(), zoneID, txtID); delErr != nil {
			log.Printf("https: не удалось удалить TXT-запись %s: %v", chalName, delErr)
		}
	}()

	log.Printf("https: TXT-запись %s создана, ждём распространения", chalName)
	waitForTXT(ctx, chalName, record, 2*time.Minute)

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("подтверждение проверки dns-01: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, az.URI); err != nil {
		return fmt.Errorf("авторизация %s: %w", az.Identifier.Value, err)
	}
	return nil
}

// baseDomainName нормализует имя домена: нижний регистр, без точек
// и wildcard-префикса.
func baseDomainName(identifier string) string {
	return strings.TrimPrefix(strings.ToLower(strings.Trim(identifier, ".")), "*.")
}

// challengeTXTName возвращает имя TXT-записи для проверки DNS-01:
// _acme-challenge.<домен>; wildcard-домен учитывается по базовому имени.
func challengeTXTName(identifier string) string {
	return "_acme-challenge." + baseDomainName(identifier)
}

// waitForTXT ждёт, пока TXT-запись станет видна через DNS. По истечении
// таймаута продолжает работу: Let's Encrypt повторяет проверку сам.
func waitForTXT(ctx context.Context, name, want string, timeout time.Duration) {
	resolver := &net.Resolver{PreferGo: true}
	deadline := time.Now().Add(timeout)
	for {
		values, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, v := range values {
				if v == want {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			log.Printf("https: TXT-запись %s не видна через %s, продолжаем без ожидания", name, timeout)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// ensureListener поднимает HTTPS-слушатель на порту port. Если слушатель
// уже работает с теми же настройками, он не трогается (сертификат
// обновляется через holder без перезапуска).
func (m *httpsManager) ensureListener(port int, host, provider string, tlsCfg *tls.Config) error {
	m.mu.Lock()
	if m.running && m.port == port && m.host == host && m.provider == provider {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	m.stopListener()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("не удалось слушать порт %d: %w", port, err)
	}
	srv := &http.Server{Handler: http.DefaultServeMux, TLSConfig: tlsCfg}
	m.mu.Lock()
	m.server = srv
	m.port = port
	m.host = host
	m.provider = provider
	m.running = true
	m.mu.Unlock()

	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("https: сервер остановлен: %v", err)
			m.mu.Lock()
			m.running = false
			m.lastError = fmt.Sprintf("HTTPS-сервер: %v", err)
			m.mu.Unlock()
		}
	}()
	return nil
}

// stopListener гасит HTTPS-слушатель, если он запущен.
func (m *httpsManager) stopListener() {
	m.mu.Lock()
	srv := m.server
	m.server = nil
	m.running = false
	m.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// startACMEResponder поднимает обработчик на порту 80: для режима http-01
// это проверка ACME и редирект на https, для DNS-01 — только редирект.
func startACMEResponder() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if mgr := httpsMgr.autocert.Load(); mgr != nil {
			mgr.HTTPHandler(http.HandlerFunc(redirectToHTTPS)).ServeHTTP(w, r)
			return
		}
		redirectToHTTPS(w, r)
	})
	srv := &http.Server{Addr: ":http", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("https: обработчик на порту 80 недоступен: %v", err)
		}
	}()
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port := httpsMgr.snapshot().Port
	if port == 0 {
		port = tlsDefaultPort
	}
	target := "https://" + host
	if port != 443 {
		target = fmt.Sprintf("https://%s:%d", host, port)
	}
	http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// getHttpsStatus отдаёт состояние HTTPS для веб-интерфейса.
func (s *Server) getHttpsStatus(w http.ResponseWriter, r *http.Request) {
	st := httpsMgr.snapshot()
	cfg, _ := loadConfig(dataFile)
	if cfg != nil {
		st.Enabled = cfg.TLSEnabled
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

// applyHttps запускает повторное применение настроек HTTPS (создание
// A-записи, выпуск/продление сертификата, поднятие слушателя).
func (s *Server) applyHttps(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	go applyTLSFromConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "provisioning"})
}

// normalizeTLSProvider приводит значение провайдера к допустимому.
func normalizeTLSProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case tlsProviderCloudflare:
		return tlsProviderCloudflare
	default:
		return tlsProviderHTTP01
	}
}

// tlsCacheDir возвращает папку кэша TLS из конфига.
func tlsCacheDir(cfg *Config) string {
	if cfg != nil && strings.TrimSpace(cfg.TLSCache) != "" {
		return strings.TrimSpace(cfg.TLSCache)
	}
	return "data/tls-cache"
}

// certFileBase возвращает безопасное имя файла для домена: точки
// сохраняются, wildcard и разделители пути заменяются.
func certFileBase(host string) string {
	base := strings.ToLower(strings.Trim(host, "."))
	base = strings.ReplaceAll(base, "*", "_")
	base = strings.ReplaceAll(base, "/", "_")
	base = strings.ReplaceAll(base, string(filepath.Separator), "_")
	if base == "" {
		base = "cert"
	}
	return base
}

// certPaths возвращает пути файлов сертификата и ключа для host.
func certPaths(cacheDir, host string) (certFile, keyFile string) {
	base := certFileBase(host)
	return filepath.Join(cacheDir, base+".crt"), filepath.Join(cacheDir, base+".key")
}

// certKeyPath возвращает путь файла ключа сертификата.
func certKeyPath(cacheDir, host string) string {
	_, keyFile := certPaths(cacheDir, host)
	return keyFile
}

// loadOrCreateECKey загружает EC-ключ P-256 из PEM-файла или создаёт новый.
func loadOrCreateECKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if k, ok := key.(*ecdsa.PrivateKey); ok {
					return k, nil
				}
			}
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var buf strings.Builder
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, []byte(buf.String())); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0600)
	return key, nil
}
