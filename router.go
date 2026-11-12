package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type keeneticImportResult struct {
	Created    string
	Intersects string
	Messages   []string
}

const (
	// keeneticClientTimeout — базовый таймаут запросов к роутеру.
	keeneticClientTimeout = 60 * time.Second
	// keeneticRciDumpTimeout — таймаут для полных дампов /rci/
	// (object-groups, интерфейсы): на загруженных роутерах они
	// отдаются дольше обычных запросов.
	keeneticRciDumpTimeout = 120 * time.Second
)

// routerSchemeCache хранит схему (http/https), с которой роутер уже
// отвечал успешно, чтобы при следующих подключениях не пробовать вторую.
var (
	routerSchemeMu    sync.Mutex
	routerSchemeCache = make(map[string]string)
)

func rememberRouterScheme(domain, scheme string) {
	routerSchemeMu.Lock()
	routerSchemeCache[strings.ToLower(strings.TrimSpace(domain))] = scheme
	routerSchemeMu.Unlock()
}

func cachedRouterScheme(domain string) string {
	routerSchemeMu.Lock()
	defer routerSchemeMu.Unlock()
	return routerSchemeCache[strings.ToLower(strings.TrimSpace(domain))]
}

// routerBaseURLs возвращает кандидатов базовых URL для подключения к
// роутеру в порядке предпочтения. Явная схема в адресе (http:// или
// https://) используется как есть. Для IP-адреса сначала пробуется http,
// для доменного имени — https. Если схема уже подтверждалась успешным
// подключением, она идёт первой.
func routerBaseURLs(domain string) []string {
	d := strings.TrimSpace(domain)
	lower := strings.ToLower(d)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return []string{strings.TrimRight(d, "/")}
	}
	addr := d
	host := d
	if h, _, err := net.SplitHostPort(d); err == nil {
		host = h
	}
	schemes := []string{"https", "http"}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		schemes = []string{"http", "https"}
		// IPv6 без скобок оборачиваем: http://[::1]
		if net.ParseIP(d) != nil && strings.Contains(d, ":") {
			addr = "[" + d + "]"
		}
	}
	if cached := cachedRouterScheme(d); cached != "" && cached != schemes[0] {
		schemes = []string{cached, schemes[0]}
	}
	urls := make([]string, 0, len(schemes))
	for _, scheme := range schemes {
		urls = append(urls, scheme+"://"+addr)
	}
	return urls
}

func keeneticAuth(httpClient *http.Client, baseURL, login, password string) error {
	authURL := baseURL + "/auth"
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return fmt.Errorf("auth request failed: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	resp.Body.Close()

	challenge := strings.TrimSpace(resp.Header.Get("X-NDM-Challenge"))
	realm := strings.TrimSpace(resp.Header.Get("X-NDM-Realm"))
	if challenge == "" || realm == "" {
		return fmt.Errorf("роутер не поддерживает NDMS auth")
	}

	md5Input := login + ":" + realm + ":" + password
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(md5Input)))
	sha256Hash := fmt.Sprintf("%x", sha256.Sum256([]byte(challenge+md5Hash)))

	authPayload := map[string]string{"login": login, "password": sha256Hash}
	authBody, _ := json.Marshal(authPayload)
	req, _ = http.NewRequest("POST", authURL, bytes.NewReader(authBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func newKeeneticClient() *http.Client {
	return &http.Client{
		Jar:     mustCookieJar(),
		Timeout: keeneticClientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func mustCookieJar() *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func keeneticSetupClient(domain, login, password string) (*http.Client, string, error) {
	for _, baseURL := range routerBaseURLs(domain) {
		client := newKeeneticClient()
		if strings.HasPrefix(baseURL, "https://") {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		if err := keeneticAuth(client, baseURL, login, password); err == nil {
			rememberRouterScheme(domain, strings.SplitN(baseURL, "://", 2)[0])
			return client, baseURL, nil
		}
	}
	return nil, "", fmt.Errorf("auth failed for %s", domain)
}

// keeneticGetWithTimeout выполняет GET с таймаутом, отличным от базового
// таймаута клиента (например, для полных дампов /rci/).
func keeneticGetWithTimeout(httpClient *http.Client, url string, timeout time.Duration) (*http.Response, error) {
	c := *httpClient
	c.Timeout = timeout
	return c.Get(url)
}

func keeneticRciPost(httpClient *http.Client, baseURL string, payload any) ([]byte, int, error) {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", baseURL+"/rci/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("rci request failed: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return data, resp.StatusCode, nil
}

func keeneticSave(httpClient *http.Client, baseURL string) error {
	payload := map[string]any{
		"system": map[string]any{
			"configuration": map[string]any{"save": "1"},
		},
	}
	data, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("save failed (HTTP %d): %s", status, strings.TrimSpace(string(data)))
	}
	time.Sleep(150 * time.Millisecond)
	return nil
}

func keeneticGetInterfaces(httpClient *http.Client, baseURL string) (map[string]string, error) {
	resp, err := keeneticGetWithTimeout(httpClient, baseURL+"/rci/", keeneticRciDumpTimeout)
	if err != nil {
		return nil, fmt.Errorf("get interfaces failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse interfaces failed: %v", err)
	}
	interfaces, ok := parsed["interface"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no interface section in response")
	}
	result := make(map[string]string)
	for name, iface := range interfaces {
		ifaceMap, ok := iface.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := ifaceMap["description"].(string)
		result[name] = desc
	}
	return result, nil
}

func keeneticGetObjectGroups(httpClient *http.Client, baseURL string) ([]string, error) {
	resp, err := keeneticGetWithTimeout(httpClient, baseURL+"/rci/", keeneticRciDumpTimeout)
	if err != nil {
		return nil, fmt.Errorf("get object-groups failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse object-groups failed: %v", err)
	}
	og, ok := parsed["object-group"].(map[string]any)
	if !ok {
		return nil, nil
	}
	fqdn, ok := og["fqdn"].(map[string]any)
	if !ok {
		return nil, nil
	}
	var names []string
	for name := range fqdn {
		names = append(names, name)
	}
	return names, nil
}

func keeneticRemoveInterface(httpClient *http.Client, baseURL, ifaceName string) error {
	payload := map[string]any{
		"interface": map[string]any{
			"name": ifaceName,
			"no":   true,
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	respStr := strings.TrimSpace(string(body))
	if status != http.StatusOK {
		return fmt.Errorf("remove interface failed (HTTP %d): %s", status, respStr)
	}
	log.Printf("RCI removeInterface: removed %s", ifaceName)
	time.Sleep(200 * time.Millisecond)
	return nil
}

func getActualServerPublicKey() string {
	out, err := execWithTimeout(5*time.Second, "wg", "show", "wg0", "public-key")
	if err != nil {
		log.Printf("getActualServerPublicKey: wg show public-key failed: %v", err)
		return ""
	}
	pub := strings.TrimSpace(string(out))
	if pub != "" && pub != "(hidden)" && pub != "(none)" && len(pub) == 44 {
		return pub
	}
	log.Printf("getActualServerPublicKey: empty/invalid (%q)", pub)
	return ""
}

func applyServerPrivateKey(priv string) error {
	tmp, err := os.CreateTemp("", "wg-priv-*.key")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(priv); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	out, err := execWithTimeout(5*time.Second, "wg", "set", "wg0", "private-key", tmpName)
	if err != nil {
		return fmt.Errorf("wg set private-key failed: %v, output: %s", err, string(out))
	}
	return nil
}

func getActualServerPrivateKey() string {
	out, err := execWithTimeout(5*time.Second, "wg", "show", "wg0", "private-key")
	if err != nil {
		log.Printf("getActualServerPrivateKey: wg show private-key failed: %v", err)
		return ""
	}
	priv := strings.TrimSpace(string(out))
	if priv != "" && priv != "(hidden)" && priv != "(none)" && len(priv) == 44 {
		if len(priv) >= 8 {
			log.Printf("getActualServerPrivateKey: synced (starts %s)", priv[:8])
		}
		return priv
	}
	log.Printf("getActualServerPrivateKey: empty/invalid (%q)", priv)
	return ""
}

func syncServerKeyFromRunning() {
	actualPriv := getActualServerPrivateKey()
	if actualPriv == "" {
		log.Printf("syncServerKey: no running interface, keeping existing key")
		return
	}
	if err := savePrivateKey(serverPrivateKeyFile, actualPriv); err != nil {
		log.Printf("syncServerKey: failed to save: %v", err)
		return
	}
	actualPub := getActualServerPublicKey()
	pubLog := actualPub
	if len(pubLog) > 12 {
		pubLog = pubLog[:12]
	}
	log.Printf("syncServerKey: synced pubkey=%s...", pubLog)
}

func parseCIDRToMask(cidr string) (string, string) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet == nil {
		return "", ""
	}
	ip = ip.To4()
	if ip == nil {
		return "", ""
	}
	mask := ipnet.Mask
	if len(mask) == 4 {
		return ip.String(), fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return ip.String(), "255.255.255.255"
}

func keeneticEnableComponent(httpClient *http.Client, baseURL, name string) error {
	installPayload := map[string]any{
		"components": map[string]any{
			"install": []any{
				map[string]any{"component": name},
			},
		},
	}
	if pBytes, err2 := json.Marshal(installPayload); err2 == nil {
		log.Printf("RCI enableComponent %s install payload: %s", name, string(pBytes))
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, installPayload)
	respStr := strings.TrimSpace(string(body))
	if err != nil {
		return fmt.Errorf("install failed for %s: %v", name, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("install %s failed (HTTP %d): %s", name, status, respStr)
	}
	if strings.Contains(respStr, `"status":"error"`) {
		return fmt.Errorf("install %s command error: %s", name, respStr)
	}
	if respStr != "" && respStr != "{}" && respStr != "[]" {
		log.Printf("RCI enableComponent %s install response: %s", name, respStr)
	}

	commitPayload := map[string]any{
		"components": map[string]any{
			"commit": map[string]any{},
		},
	}
	body, status, err = keeneticRciPost(httpClient, baseURL, commitPayload)
	respStr = strings.TrimSpace(string(body))
	if err != nil {
		return fmt.Errorf("commit failed for %s: %v", name, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("commit %s failed (HTTP %d): %s", name, status, respStr)
	}
	if respStr != "" && respStr != "{}" && respStr != "[]" {
		log.Printf("RCI enableComponent %s commit response: %s", name, respStr)
	}

	log.Printf("RCI enableComponent: %s", name)
	time.Sleep(200 * time.Millisecond)
	return nil
}

func keeneticBatchInstallComponents(httpClient *http.Client, baseURL string, names []string) error {
	if len(names) == 0 {
		return nil
	}

	installItems := make([]any, 0, len(names))
	for _, name := range names {
		installItems = append(installItems, map[string]any{
			"component": name,
		})
	}
	payload := map[string]any{
		"components": map[string]any{
			"install": installItems,
		},
	}
	if pBytes, err2 := json.Marshal(payload); err2 == nil {
		log.Printf("RCI batchInstallComponents install payload: %s", string(pBytes))
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	respStr := strings.TrimSpace(string(body))
	if err != nil {
		return fmt.Errorf("install phase failed: %v", err)
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return fmt.Errorf("install phase rejected HTTP %d: %s", status, respStr)
	}
	if strings.Contains(respStr, `"status":"error"`) {
		return fmt.Errorf("install command error: %s", respStr)
	}
	log.Printf("RCI batchInstallComponents install response: %s", respStr)

	commitPayload := map[string]any{
		"components": map[string]any{
			"commit": map[string]any{},
		},
	}
	if pBytes, err2 := json.Marshal(commitPayload); err2 == nil {
		log.Printf("RCI batchInstallComponents commit payload: %s", string(pBytes))
	}
	body, status, err = keeneticRciPost(httpClient, baseURL, commitPayload)
	respStr = strings.TrimSpace(string(body))
	if err != nil {
		return fmt.Errorf("commit phase failed: %v", err)
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return fmt.Errorf("commit phase rejected HTTP %d: %s", status, respStr)
	}
	log.Printf("RCI batchInstallComponents commit response: %s", respStr)

	return nil
}

type ComponentInfo struct {
	Name         string
	Description  string
	Installed    bool
	RawInstalled string
	Size         int
}

func keeneticGetComponents(httpClient *http.Client, baseURL string) (map[string]ComponentInfo, error) {
	payload := map[string]any{
		"components": map[string]any{
			"list": map[string]any{},
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return nil, fmt.Errorf("components list request failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("components list HTTP %d", status)
	}

	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("components list parse error: %v", err)
	}

	result := make(map[string]ComponentInfo)

	comps, ok := resp["components"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no components key in response")
	}
	list, ok := comps["list"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no components.list key in response")
	}

	if componentDict, ok := list["component"].(map[string]any); ok {
		for name, data := range componentDict {
			if compMap, ok := data.(map[string]any); ok {
				info := parseComponentInfo(name, compMap)
				result[name] = info
			}
		}
	}

	for name, data := range list {
		if name == "component" || name == "continued" || name == "firmware" || name == "sandbox" || name == "local" || name == "group" || name == "changelog" {
			continue
		}
		if compMap, ok := data.(map[string]any); ok {
			if _, exists := result[name]; !exists {
				info := parseComponentInfo(name, compMap)
				result[name] = info
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no components found in response")
	}

	log.Printf("RCI keeneticGetComponents: found %d components", len(result))
	return result, nil
}

func isSystemComponent(name string) bool {
	systemComponents := map[string]bool{
		"firmware": true, "local": true, "component": true, "group": true,
		"sandbox": true, "changelog": true, "base": true,
	}
	return systemComponents[name]
}

func parseComponentInfo(name string, compMap map[string]any) ComponentInfo {
	info := ComponentInfo{Name: name}
	if descObj, ok := compMap["description"].(map[string]any); ok {
		if enDesc, ok := descObj["EN"].(string); ok {
			info.Description = enDesc
		} else {
			for _, v := range descObj {
				if s, ok := v.(string); ok && s != "" {
					info.Description = s
					break
				}
			}
		}
	} else if descStr, ok := compMap["description"].(string); ok {
		info.Description = descStr
	}
	if installed, ok := compMap["installed"].(bool); ok {
		info.RawInstalled = fmt.Sprintf("%v", installed)
		info.Installed = installed
	} else if installedStr, ok := compMap["installed"].(string); ok && installedStr != "" {
		info.RawInstalled = installedStr
		lower := strings.ToLower(installedStr)
		switch lower {
		case "false", "0", "no", "off":
			info.Installed = false
		default:
			// "true"/"1"/"yes"/"on", версии вида "1.2.3" и прочие значения
			// означают установленный компонент.
			info.Installed = true
		}
	}
	if size, ok := compMap["size"].(float64); ok {
		info.Size = int(size)
	} else if sizeStr, ok := compMap["size"].(string); ok {
		if parsed, err := strconv.Atoi(sizeStr); err == nil {
			info.Size = parsed
		}
	}
	return info
}

func keeneticSetDnsRoutes(httpClient *http.Client, baseURL, wanIface string, enabled bool) error {
	val := "false"
	if enabled {
		val = "true"
	}
	payload := map[string]any{
		"interface": map[string]any{
			"name": wanIface,
			"ip": map[string]any{
				"dhcp": map[string]any{
					"client": map[string]any{
						"dns-routes": val,
					},
				},
			},
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	respStr := strings.TrimSpace(string(body))
	if status != http.StatusOK {
		return fmt.Errorf("set dns-routes failed (HTTP %d): %s", status, respStr)
	}
	log.Printf("RCI setDnsRoutes: iface=%s enabled=%v", wanIface, enabled)
	time.Sleep(200 * time.Millisecond)
	return nil
}
