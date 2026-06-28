package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
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
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

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
