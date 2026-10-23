package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type componentResult struct {
	Peer      string   `json:"peer"`
	Interface string   `json:"interface,omitempty"`
	Messages  []string `json:"messages"`
	Status    string   `json:"status"`
}

func componentsAppendLog(msg string) {
	f, err := os.OpenFile(filepath.Join(logDir, "components-apply.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg)
}

func findComponent(components map[string]ComponentInfo, target string) (ComponentInfo, bool) {
	if info, ok := components[target]; ok {
		return info, true
	}
	lower := strings.ToLower(target)
	for key, info := range components {
		if strings.ToLower(key) == lower {
			return info, true
		}
	}
	return ComponentInfo{}, false
}

func configureRouterComponents(httpClient *http.Client, baseURL string, peer *Peer, serverPub, serverEndpoint string, serverPort int, wanInterface string) componentResult {
	result := componentResult{Peer: peer.Name, Status: "ok", Messages: []string{}}

	componentsAppendLog("=== Настройка компонентов ===\n")

	targets := []string{"wireguard", "dns-tls"}

	componentsAppendLog("🔎 Проверка доступных компонентов...\n")
	components, err := keeneticGetComponents(httpClient, baseURL)
	if err != nil {
		msg := fmt.Sprintf("⚠️ ошибка получения компонентов: %s", err.Error())
		componentsAppendLog(msg + "\n")
		result.Status = "error"
		result.Messages = append(result.Messages, msg)
		return result
	}

	var toInstall []string
	for _, target := range targets {
		info, found := findComponent(components, target)
		if found && info.Installed {
			desc := info.Description
			if desc == "" {
				desc = info.Name
			}
			msg := fmt.Sprintf("✅ Компонент %s (%s) уже установлен", info.Name, desc)
			componentsAppendLog(msg + "\n")
			result.Messages = append(result.Messages, msg)
		} else {
			toInstall = append(toInstall, target)
			if found {
				componentsAppendLog(fmt.Sprintf("⚠️ Компонент %s найден, но не установлен\n", info.Name))
			} else {
				componentsAppendLog(fmt.Sprintf("⚠️ Компонент %s не найден — установка по имени\n", target))
			}
		}
	}

	if len(toInstall) == 0 {
		componentsAppendLog("=== Все компоненты уже установлены ===\n")
		result.Messages = append(result.Messages, "✅ все компоненты уже установлены")
		return result
	}

	componentsAppendLog(fmt.Sprintf("📦 Пакетная установка: %v\n", toInstall))
	if err := keeneticBatchInstallComponents(httpClient, baseURL, toInstall); err != nil {
		msg := fmt.Sprintf("❌ Пакетная установка отклонена: %s", err.Error())
		componentsAppendLog(msg + "\n")
		result.Status = "error"
		result.Messages = append(result.Messages, msg)
		return result
	}

	componentsAppendLog("⏳ Ожидание перезагрузки роутера (180с)...\n")
	os.WriteFile(filepath.Join(logDir, "components-apply.status"), []byte("waiting_reboot"), 0644)
	time.Sleep(180 * time.Second)

	componentsAppendLog("🔄 Переподключение...\n")
	client := httpClient
	if peer.RouterLogin != "" && peer.RouterPassword != "" {
		componentsAppendLog("🔄 Переавторизация...\n")
		domain := strings.TrimPrefix(baseURL, "https://")
		domain = strings.TrimPrefix(domain, "http://")
		newClient, newURL, authErr := keeneticSetupClient(domain, peer.RouterLogin, peer.RouterPassword)
		if authErr == nil {
			client = newClient
			baseURL = newURL
			componentsAppendLog("✅ Переавторизация успешна\n")
		} else {
			componentsAppendLog(fmt.Sprintf("⚠️ переавторизация не удалась: %v\n", authErr))
		}
	}

	componentsAppendLog("🔎 Проверка установки...\n")
	components, err = keeneticGetComponents(client, baseURL)
	if err != nil {
		msg := fmt.Sprintf("⚠️ ошибка проверки: %s", err.Error())
		componentsAppendLog(msg + "\n")
		result.Status = "error"
		result.Messages = append(result.Messages, msg)
		return result
	}

	for _, target := range toInstall {
		info, found := findComponent(components, target)
		if found && info.Installed {
			desc := info.Description
			if desc == "" {
				desc = info.Name
			}
			msg := fmt.Sprintf("✅ Компонент %s (%s) установлен", info.Name, desc)
			componentsAppendLog(msg + "\n")
			result.Messages = append(result.Messages, msg)
		} else {
			name := target
			if found {
				name = info.Name
			}
			msg := fmt.Sprintf("❌ Компонент %s не установлен", name)
			componentsAppendLog(msg + "\n")
			result.Status = "error"
			result.Messages = append(result.Messages, msg)
		}
	}

	componentsAppendLog("=== Настройка компонентов завершена ===\n")
	return result
}
