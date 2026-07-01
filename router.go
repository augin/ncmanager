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
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type keeneticImportResult struct {
	Created    string
	Intersects string
	Messages   []string
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
		Timeout: 30 * time.Second,
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
	for _, scheme := range []string{"http", "https"} {
		baseURL := scheme + "://" + domain
		var client *http.Client
		if scheme == "https" {
			client = &http.Client{
				Jar:     mustCookieJar(),
				Timeout: 30 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		} else {
			client = newKeeneticClient()
		}
		if err := keeneticAuth(client, baseURL, login, password); err == nil {
			return client, baseURL, nil
		}
	}
	return nil, "", fmt.Errorf("auth failed for %s", domain)
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
	resp, err := httpClient.Get(baseURL + "/rci/")
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
	resp, err := httpClient.Get(baseURL + "/rci/")
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

func keeneticRenameInterface(httpClient *http.Client, baseURL, oldName, newName string) error {
	payload := map[string]any{
		"interface": map[string]any{
			oldName: map[string]any{
				"rename": newName,
			},
		},
	}
	_, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("rename failed (HTTP %d)", status)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
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
	out, err := exec.Command("wg", "show", "wg0", "public-key").CombinedOutput()
	if err != nil {
		log.Printf("getActualServerPublicKey: wg show public-key failed: %v", err)
		return ""
	}
	pub := strings.TrimSpace(string(out))
	if pub != "" && pub != "(hidden)" {
		return pub
	}
	log.Printf("getActualServerPublicKey: empty")
	return ""
}

func getActualServerPrivateKey() string {
	out, err := exec.Command("wg", "show", "wg0", "private-key").CombinedOutput()
	if err != nil {
		log.Printf("getActualServerPrivateKey: wg show private-key failed: %v", err)
		return ""
	}
	priv := strings.TrimSpace(string(out))
	if priv != "" && priv != "(hidden)" {
		log.Printf("getActualServerPrivateKey: synced (starts %s)", priv[:8])
		return priv
	}
	log.Printf("getActualServerPrivateKey: empty")
	return ""
}

func syncServerKeyFromRunning() {
	actualPriv := getActualServerPrivateKey()
	if actualPriv == "" {
		log.Printf("syncServerKey: no running interface, keeping existing key")
		return
	}
	if err := savePrivateKey("data/server_private.key", actualPriv); err != nil {
		log.Printf("syncServerKey: failed to save: %v", err)
		return
	}
	actualPub := getActualServerPublicKey()
	log.Printf("syncServerKey: synced pubkey=%s", actualPub[:12]+"...")
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

func tryDirectComponentLookup(httpClient *http.Client, baseURL string) map[string]ComponentInfo {
	targets := []string{"wireguard", "dns-tls", "dns_proxy", "wireguard-server"}
	result := make(map[string]ComponentInfo)

	for _, name := range targets {
		paths := []string{
			"/rci/components/" + name,
			"/rci/components/list/" + name,
		}
		for _, path := range paths {
			resp, err := httpClient.Get(baseURL + path)
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || len(data) < 2 {
				continue
			}

			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				continue
			}
			info := parseComponentInfo(name, obj)
			if info.Description != "" || info.Installed {
				result[name] = info
				log.Printf("RCI GET %s: found desc=%s installed=%v", path, info.Description, info.Installed)
				break
			}
			log.Printf("RCI GET %s: no description/installed, keys=%v", path, getKeys(obj))
		}
	}

	return result
}

func parseComponentsResponse(data map[string]any) (map[string]ComponentInfo, error) {
	result := make(map[string]ComponentInfo)
	skipKeys := map[string]bool{"system": true, "interface": true, "user": true, "service": true, "ip": true, "ipv6": true}

	for name, comp := range data {
		if skipKeys[name] {
			continue
		}

		compMap, ok := comp.(map[string]any)
		if !ok {
			continue
		}

		// Special handling for "components" section - it may contain real packages
		if name == "components" {
			// Try components.list first (common batch response format)
			if ls, ok := compMap["list"].(map[string]any); ok {
				for compName, compData := range ls {
					if childMap, ok := compData.(map[string]any); ok {
						// "component" is a container that holds all real packages inside
						if compName == "component" {
							scanForComponents(childMap, "", result)
							continue
						}
						info := parseComponentInfo(compName, childMap)
						if info.Description != "" || info.Installed {
							result[compName] = info
						} else {
							for _, v := range childMap {
								if _, isStr := v.(string); isStr {
									result[compName] = info
									break
								}
								if _, isNum := v.(float64); isNum {
									result[compName] = info
									break
								}
							}
						}
					}
				}
			}
			// Also scan direct children of components (GET /rci/ format)
			for compName, compData := range compMap {
				if compName == "list" {
					continue
				}
				childMap, ok := compData.(map[string]any)
				if !ok {
					continue
				}
				info := parseComponentInfo(compName, childMap)
				if info.Description != "" || info.Installed {
					result[compName] = info
				} else {
					for _, v := range childMap {
						if _, isStr := v.(string); isStr {
							result[compName] = info
							break
						}
						if _, isNum := v.(float64); isNum {
							result[compName] = info
							break
						}
					}
				}
			}
			continue
		}

		info := parseComponentInfo(name, compMap)
		if info.Description != "" || info.Installed {
			result[name] = info
		} else {
			for _, v := range compMap {
				if _, isStr := v.(string); isStr {
					result[name] = info
					break
				}
				if _, isNum := v.(float64); isNum {
					result[name] = info
					break
				}
			}
		}
	}

	filtered := make(map[string]ComponentInfo)
	for name, info := range result {
		if !isSystemComponent(name) {
			filtered[name] = info
		}
	}

	if len(filtered) > 0 {
		keys := make([]string, 0, len(filtered))
		for n := range filtered {
			keys = append(keys, n)
		}
		if len(keys) > 30 {
			keys = keys[:30]
		}
		log.Printf("RCI parseComponentsResponse: found %d components: %v", len(filtered), keys)
		return filtered, nil
	}

	log.Printf("RCI parseComponentsResponse: no components found in %d top-level keys (raw keys: %v)", len(data), getKeys(data))
	return result, nil
}

func scanForComponents(data map[string]any, path string, result map[string]ComponentInfo) {
	for name, comp := range data {
		currentPath := name
		if path != "" {
			currentPath = path + "." + name
		}

		compMap, ok := comp.(map[string]any)
		if !ok {
			continue
		}

		info := parseComponentInfo(name, compMap)
		if info.Description != "" || info.Installed {
			if !isSystemComponent(name) {
				result[name] = info
			}
			continue
		}

		hasAnyData := false
		for _, v := range compMap {
			switch val := v.(type) {
			case string:
				if val != "" {
					hasAnyData = true
				}
			case float64:
				hasAnyData = true
			case bool:
				hasAnyData = true
			case map[string]any:
				if len(val) > 0 {
					hasAnyData = true
				}
			case []any:
				if len(val) > 0 {
					hasAnyData = true
				}
			}
		}
		if hasAnyData && !isSystemComponent(name) {
			result[name] = info
			continue
		}

		scanForComponents(compMap, currentPath, result)
	}
}

func dumpComponentTree(data map[string]any, prefix string) {
	for name, comp := range data {
		compType := fmt.Sprintf("%T", comp)
		if compMap, ok := comp.(map[string]any); ok {
			log.Printf("%s%s: map with %d keys", prefix, name, len(compMap))
			if name == "components" {
				for k, v := range compMap {
					log.Printf("  %scomponents.%s: %T", prefix, k, v)
					if childMap, ok := v.(map[string]any); ok {
						for ck, cv := range childMap {
							log.Printf("    %scomponents.%s.%s: %T", prefix, k, ck, cv)
						}
					}
				}
			}
			// Also show any other map that might contain components
			if name != "components" && len(compMap) > 0 {
				count := 0
				for k, v := range compMap {
					if count >= 5 {
						break
					}
					log.Printf("  %s%s.%s: %T", prefix, name, k, v)
					if childMap, ok := v.(map[string]any); ok {
						for ck, cv := range childMap {
							if count >= 5 {
								break
							}
							log.Printf("    %s%s.%s.%s: %T", prefix, name, k, ck, cv)
						}
					}
					count++
				}
			}
		} else {
			log.Printf("%s%s: %s", prefix, name, compType)
		}
	}
}

func getKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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
		if strings.ContainsAny(lower, "0123456789.") {
			info.Installed = true
		} else if lower == "true" || lower == "1" || lower == "yes" || lower == "on" {
			info.Installed = true
		} else if lower == "false" || lower == "0" || lower == "no" || lower == "off" {
			info.Installed = false
		} else {
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
