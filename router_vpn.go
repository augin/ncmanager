package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func keeneticSetInterfaceIP(httpClient *http.Client, baseURL, ifaceName, allowedIPs string) error {
	addr, mask := parseCIDRToMask(allowedIPs)
	if addr == "" {
		return fmt.Errorf("invalid allowed ips: %s", allowedIPs)
	}
	payload := map[string]any{
		"interface": map[string]any{
			"name": ifaceName,
			"ip": map[string]any{
				"address": map[string]any{
					"address": addr,
					"mask":    mask,
				},
			},
		},
	}
	_, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("set interface ip failed (HTTP %d)", status)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func keeneticSetInterfaceName(httpClient *http.Client, baseURL, ifaceName, displayName string) error {
	payload := map[string]any{
		"interface": map[string]any{
			"name":        ifaceName,
			"description": displayName,
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	respStr := strings.TrimSpace(string(body))
	if status == http.StatusOK {
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	return fmt.Errorf("set interface description failed (HTTP %d): %s", status, respStr)
}

func keeneticSetPeer(httpClient *http.Client, baseURL, ifaceName, serverPubKey, endpoint, allowedIPs, comment string, keepalive int) error {
	peer := map[string]any{
		"key": serverPubKey,
	}
	if endpoint != "" {
		peer["endpoint"] = map[string]any{"address": endpoint}
	}
	if allowedIPs != "" {
		addr, mask := parseCIDRToMask(allowedIPs)
		if addr != "" {
			peer["allow-ips"] = []any{map[string]any{"address": addr, "mask": mask}}
		}
	}
	if keepalive > 0 {
		peer["keepalive-interval"] = map[string]any{"interval": keepalive}
	}
	if comment != "" {
		peer["comment"] = comment
	}
	payload := map[string]any{
		"interface": map[string]any{
			"name": ifaceName,
			"wireguard": map[string]any{
				"peer": []any{peer},
			},
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	respStr := strings.TrimSpace(string(body))
	log.Printf("RCI setPeer: HTTP %d body=%s", status, respStr)
	if status != http.StatusOK {
		return fmt.Errorf("set peer failed (HTTP %d): %s", status, respStr)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func keeneticRemovePeer(httpClient *http.Client, baseURL, ifaceName, serverPubKey string) error {
	payload := map[string]any{
		"interface": map[string]any{
			"name": ifaceName,
			"wireguard": map[string]any{
				"peer": []any{map[string]any{"no": true, "key": serverPubKey}},
			},
		},
	}
	body, status, err := keeneticRciPost(httpClient, baseURL, payload)
	if err != nil {
		return err
	}
	respStr := strings.TrimSpace(string(body))
	log.Printf("RCI removePeer: HTTP %d body=%s", status, respStr)
	if status != http.StatusOK {
		return fmt.Errorf("remove peer failed (HTTP %d): %s", status, respStr)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func importWireGuardConfigToRouter(baseURL, login, password string, confData []byte, filename string, interfaceIP string, peerAllowedIPs string, endpoint string, port int) (keeneticImportResult, error) {
	domain := strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
	client, workingURL, err := keeneticSetupClient(domain, login, password)
	if err != nil {
		return keeneticImportResult{}, err
	}
	httpClient := client
	baseURL = workingURL

	peerName := strings.TrimSuffix(filename, ".conf")

	if interfaces, err := keeneticGetInterfaces(httpClient, baseURL); err == nil {
		for existingName, desc := range interfaces {
			if desc == peerName {
				log.Printf("keenetic import: removing existing interface %s (description=%q) before re-import", existingName, desc)
				if err := keeneticRemoveInterface(httpClient, baseURL, existingName); err != nil {
					log.Printf("keenetic remove existing interface %s failed: %v", existingName, err)
				} else {
					log.Printf("keenetic import: removed existing interface %s", existingName)
				}
				time.Sleep(300 * time.Millisecond)
				break
			}
		}
	}

	encoded := base64.StdEncoding.EncodeToString(confData)

	importPayload := map[string]any{
		"interface": map[string]any{
			"wireguard": map[string]any{
				"import":   encoded,
				"name":     "",
				"filename": filename,
			},
		},
	}
	respBody, status, err := keeneticRciPost(httpClient, baseURL, importPayload)
	if err != nil {
		return keeneticImportResult{}, err
	}
	if status != http.StatusOK {
		return keeneticImportResult{}, fmt.Errorf("import failed (HTTP %d): %s", status, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Interface struct {
			Wireguard struct {
				Import struct {
					Created    string `json:"created"`
					Intersects string `json:"intersects"`
					Status     []struct {
						Message string `json:"message"`
					} `json:"status"`
				} `json:"import"`
			} `json:"wireguard"`
		} `json:"interface"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return keeneticImportResult{}, fmt.Errorf("parse response failed: %v", err)
	}

	result := keeneticImportResult{
		Created:    parsed.Interface.Wireguard.Import.Created,
		Intersects: parsed.Interface.Wireguard.Import.Intersects,
	}
	for _, s := range parsed.Interface.Wireguard.Import.Status {
		if s.Message != "" {
			result.Messages = append(result.Messages, s.Message)
		}
	}

	// Determine final interface name
	ifaceName := result.Created
	if ifaceName == "" {
		ifaceName = result.Intersects
	}
	if ifaceName == "" {
		return result, fmt.Errorf("router returned no interface name; status: %s", strings.Join(result.Messages, "; "))
	}

	// If there's an existing orphan interface with no description,
	// rename it to match this peer (avoid duplicates)
	if interfaces, err := keeneticGetInterfaces(httpClient, baseURL); err == nil {
		for existingName, desc := range interfaces {
			if desc == "" && ifaceName == "" {
				descPayload := map[string]any{"interface": map[string]any{"name": existingName, "description": peerName}}
				keeneticRciPost(httpClient, baseURL, descPayload)
				time.Sleep(200 * time.Millisecond)
				result.Messages = append(result.Messages, "ℹ️ orphan "+existingName+" назначен peer=\""+peerName+"\"")
				ifaceName = existingName
				result.Created = existingName
				break
			}
		}
	}

	// Set the interface display name
	if ifaceName != "" && peerName != "" {
		if err := keeneticSetInterfaceName(httpClient, baseURL, ifaceName, peerName); err != nil {
			log.Printf("keenetic set name %s -> %s failed: %v", ifaceName, peerName, err)
			result.Messages = append(result.Messages, "⚠️ установка имени интерфейса: "+err.Error())
		} else {
			result.Messages = append(result.Messages, "✅ имя интерфейса: "+peerName)
		}
	}

	// Set the interface IP address
	if ifaceName != "" && interfaceIP != "" {
		if err := keeneticSetInterfaceIP(httpClient, baseURL, ifaceName, interfaceIP); err != nil {
			log.Printf("keenetic set ip %s -> %s failed: %v", ifaceName, interfaceIP, err)
			result.Messages = append(result.Messages, "⚠️ установка IP: "+err.Error())
		} else {
			result.Messages = append(result.Messages, "✅ IP адрес установлен: "+interfaceIP)
		}
	}

	// Set peer settings (endpoint, allowed-ips, keepalive, comment) in one call
	if ifaceName != "" {
		serverPub := getActualServerPublicKey()
		if serverPub == "" {
			if serverPrivBytes, err := loadPrivateKey("data/server_private.key"); err == nil {
				if sp, err := getPublicKeyFromPrivate(serverPrivBytes); err == nil {
					serverPub = strings.TrimSpace(string(sp))
				}
			}
		}
		if serverPub != "" {
			peerEndpoint := fmt.Sprintf("%s:%d", endpoint, port)
			if err := keeneticRemovePeer(httpClient, baseURL, ifaceName, serverPub); err != nil {
				result.Messages = append(result.Messages, "⚠️ удаление старого peer: "+err.Error())
			} else {
				result.Messages = append(result.Messages, "🧹 старый peer удалён")
			}
			if err := keeneticSetPeer(httpClient, baseURL, ifaceName, serverPub, peerEndpoint, peerAllowedIPs, peerName, 25); err != nil {
				result.Messages = append(result.Messages, "⚠️ Peer: "+err.Error())
			} else {
				result.Messages = append(result.Messages, "✅ Peer: endpoint="+peerEndpoint+" allow-ips="+peerAllowedIPs+" keepalive=25")
			}
		}
	}

	// Enable the interface (up + save)
	result.Created = ifaceName
	upPayload := map[string]any{"interface": map[string]any{"name": ifaceName, "up": true}}
	if data, status, err := keeneticRciPost(httpClient, baseURL, upPayload); err != nil {
		result.Messages = append(result.Messages, "⚠️ активация: "+err.Error())
	} else if status != http.StatusOK {
		result.Messages = append(result.Messages, fmt.Sprintf("⚠️ активация: HTTP %d %s", status, strings.TrimSpace(string(data))))
	} else {
		result.Messages = append(result.Messages, "✅ интерфейс активирован")
	}

	if err := keeneticSave(httpClient, baseURL); err != nil {
		result.Messages = append(result.Messages, "⚠️ сохранение: "+err.Error())
	} else {
		result.Messages = append(result.Messages, "✅ конфигурация сохранена")
	}

	return result, nil
}
