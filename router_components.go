package main

import (
	"fmt"
	"net/http"
	"os"
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
	f, err := os.OpenFile("/tmp/components-apply.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg)
}

func ensureComponent(httpClient *http.Client, baseURL, login, password, targetName string) (*http.Client, bool, string) {
	const maxAttempts = 3
	const rebootWait = 180 * time.Second
	const checkInterval = 60 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		componentsAppendLog(fmt.Sprintf("🔎 Поиск компонента %s (попытка %d/%d)...\n", targetName, attempt, maxAttempts))

		components, err := keeneticGetComponents(httpClient, baseURL)
		if err != nil {
			componentsAppendLog(fmt.Sprintf("⚠️ ошибка получения компонентов: %s\n", err.Error()))
			if attempt < maxAttempts {
				componentsAppendLog(fmt.Sprintf("⏳ Ожидание (%s) перед повторной попыткой...\n", checkInterval))
				time.Sleep(checkInterval)
				continue
			}
			return httpClient, false, "⚠️ проверка компонентов: " + err.Error()
		}

		info, found := findComponent(components, targetName)
		if found && info.Installed {
			foundName := info.Name
			foundDesc := info.Description
			if foundDesc == "" {
				foundDesc = foundName
			}
			componentsAppendLog(fmt.Sprintf("✅ Компонент %s (%s) уже установлен\n", foundName, foundDesc))
			return httpClient, true, fmt.Sprintf("✅ компонент %s (%s) уже установлен", foundName, foundDesc)
		}

		if found && !info.Installed {
			componentsAppendLog(fmt.Sprintf("⚠️ Компонент %s найден, но не установлен — требуется установка (raw_installed=%q)\n", info.Name, info.RawInstalled))
		}

		if attempt < maxAttempts {
			installKey := targetName
			if found {
				installKey = info.Name
			}
			componentsAppendLog(fmt.Sprintf("📦 Устанавливаю компонент %s (ключ: %s)...\n", targetName, installKey))
			if err := keeneticEnableComponent(httpClient, baseURL, installKey); err != nil {
				componentsAppendLog(fmt.Sprintf("❌ не удалось установить %s: %s\n", targetName, err.Error()))
				return httpClient, false, fmt.Sprintf("❌ не удалось установить %s: %s", targetName, err.Error())
			}
			componentsAppendLog(fmt.Sprintf("⏳ Ожидание перезагрузки роутера (%s)...\n", rebootWait))
			os.WriteFile("/tmp/components-apply.status", []byte(fmt.Sprintf("waiting_reboot_%s", targetName)), 0644)
			ticker := time.NewTicker(30 * time.Second)
			tickerWaitDone := make(chan bool)
			go func() {
				waitEnd := time.Now().Add(rebootWait)
				for time.Now().Before(waitEnd) {
					<-ticker.C
					remaining := int(time.Until(waitEnd).Seconds())
					componentsAppendLog(fmt.Sprintf("⏳ Ожидание перезагрузки... осталось %d сек\n", remaining))
					os.WriteFile("/tmp/components-apply.status", []byte(fmt.Sprintf("waiting_reboot_%s_%ds", targetName, remaining)), 0644)
				}
				ticker.Stop()
				tickerWaitDone <- true
			}()
			<-tickerWaitDone
			componentsAppendLog(fmt.Sprintf("🔄 Переподключение к роутеру...\n"))
			if login != "" && password != "" {
				componentsAppendLog("🔄 Переавторизация после перезагрузки роутера...\n")
				domain := strings.TrimPrefix(baseURL, "https://")
				domain = strings.TrimPrefix(domain, "http://")
				newClient, newURL, authErr := keeneticSetupClient(domain, login, password)
				if authErr == nil {
					httpClient = newClient
					baseURL = newURL
					componentsAppendLog("✅ Переавторизация успешна\n")
				} else {
					componentsAppendLog(fmt.Sprintf("⚠️ переавторизация не удалась: %v\n", authErr))
				}
			}
		} else {
			componentsAppendLog(fmt.Sprintf("❌ Компонент %s не найден после %d попыток\n", targetName, maxAttempts))
			return httpClient, false, fmt.Sprintf("❌ компонент %s не найден после %d попыток", targetName, maxAttempts)
		}
	}

	return httpClient, false, fmt.Sprintf("❌ не удалось установить %s", targetName)
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

func getComponentNames(components map[string]ComponentInfo) []string {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	return names
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
	os.WriteFile("/tmp/components-apply.status", []byte("waiting_reboot"), 0644)
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
