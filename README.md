# ncmanager

Управление WireGuard-пирами на роутерах Keenetic через веб-интерфейс и RCI API.

## Возможности

- Создание/удаление пиров WireGuard
- Автоматическая настройка WireGuard интерфейса на роутере Keenetic через RCI (импорт .conf файла)
- Установка компонентов роутера (wireguard, dns-tls) — пакетная установка с одной перезагрузкой
- Настройка DoT-серверов (Quad9, Cloudflare, Яндекс с доменной фильтрацией)
- DNS-маршрутизация: доменные и CIDR-правила, применяемые к каждому пиру отдельно
- Библиотека пресетов DNS-маршрутов (75+ категорий)
- Аутентификация по паролю
- Статус WireGuard (handshake, трафик, endpoint)

## Требования

- Сервер с Go 1.21+ (для сборки) или Linux amd64/arm64 (для бинарника)
- Инструменты `wg` и `wg-quick` на сервере
- Права root (для управления WireGuard интерфейсом)
- Роутер Keenetic с RCI (KeeneticOS 3.x+, поддержка DNS-over-TLS и WireGuard)

## Установка

### Вариант 1: Скачать готовый бинарник

Linux amd64:
```bash
curl -L -o wg-manager https://github.com/augin/ncmanager/releases/download/v1.0.0/wg-manager-linux-amd64
chmod +x wg-manager
```

Linux arm64:
```bash
curl -L -o wg-manager https://github.com/augin/ncmanager/releases/download/v1.0.0/wg-manager-linux-arm64
chmod +x wg-manager
```

### Вариант 2: Собрать из исходников

```bash
git clone https://github.com/augin/ncmanager.git
cd ncmanager
go build -o wg-manager .
```

## Запуск

```bash
sudo ./wg-manager
```

По умолчанию:
- Веб-интерфейс: `8080`
- WireGuard порт: `51820`
- Интерфейс: `wg0`
- Файл глобальных настроек: `data/config.json`
- Файл настроек пиров: `data/peers.json`
- Файл конфигурации: `data/wg0.conf`

### Открытие порта в firewall

```bash
sudo ufw allow 51820/udp
```

Или `iptables`:
```bash
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

## Первый запуск

1. Откройте `http://<ваш-сервер>:8080` в браузере.
2. Введите пароль (по умолчанию: `admin`).
3. Добавьте первого пира через «Добавить пира».
4. Укажите домен роутера, логин и пароль от веб-интерфейса Keenetic.
5. Нажмите «Настроить компоненты» — установятся wireguard и dns-tls (одна перезагрузка).
6. Нажмите «Настроить VPN» — импорт конфигурации через RCI.
7. Нажмите «Настроить DNS» — пропишутся DoT-серверы.

## Настройка роутера Keenetic

Для настройки через RCI укажите для пира:
- Домен роутера (`Router Domain`)
- Логин и пароль от веб-интерфейса роутера
- Имя интерфейса (по умолчанию `Wireguard0`)

### Кнопки управления

| Кнопка | Действие |
|--------|----------|
| **Настроить компоненты** | Устанавливает компоненты `wireguard` и `dns-tls` через RCI. Пакетная установка — роутер перезагружается один раз. |
| **Настроить VPN** | Импортирует .conf на роутер, настраивает peer (endpoint, allowed-ips, keepalive), активирует интерфейс. |
| **Настроить DNS** | Прописывает DoT-серверы: Quad9 (9.9.9.9), Cloudflare (1.1.1.1), Яндекс (77.88.8.8 с доменами ru, su, рф). |
| **Настроить DNS-маршрутизацию** | Включает/выключает DNS-маршрутизацию на интерфейсе роутера. |

### RCI-форматы

ncmanager использует следующие RCI-команды, проверенные на реальных роутерах KeeneticOS 5.x:

**Установка компонентов:**
```json
{"components":{"install":[{"component":"wireguard"},{"component":"dns-tls"}]}}
{"components":{"commit":{}}}
```

**DoT-серверы:**
```json
{"dns-proxy":{"tls":{"upstream":[
  {"address":"9.9.9.9","fqdn":"dns.quad9.net"},
  {"address":"77.88.8.8","fqdn":"common.dot.dns.yandex.net","domain":"ru"}
]}}}
```

**DNS-маршруты:**
```json
{"object-group":{"fqdn":{"group_p1":{"include":[{"address":"example.com"}]}}}}
{"dns-proxy":{"route":[{"group":"group_p1","interface":"Wireguard0","auto":true}]}}
```

## Остановка

```bash
sudo wg-quick down wg0
```

## Структура проекта

```
ncmanager/
├── main.go                # Точка входа, обработчики API
├── router.go              # RCI-клиент (авторизация, POST, парсинг компонентов)
├── router_components.go   # Установка компонентов роутера (wireguard, dns-tls)
├── router_dns.go          # Настройка DoT-серверов
├── router_vpn.go          # Настройка VPN (импорт, peer, интерфейс)
├── dns_routing.go         # DNS-маршрутизация, пресеты, CRUD маршрутов
├── static/js/app.js       # Веб-интерфейс
├── templates/index.html   # HTML-шаблон
├── presets/
│   └── dns-routes.json    # Пресеты DNS-маршрутов
└── data/
    ├── config.json        # Глобальные настройки (создаётся автоматически)
    └── peers.json         # Пиры и DNS-маршруты (создаётся автоматически)
```

## API

Все endpoints кроме `/` требуют базовую аутентификацию.

| Метод | Endpoint | Описание |
|-------|----------|----------|
| GET | `/status` | Статус WireGuard |
| GET | `/config` | Текущая конфигурация |
| POST | `/peers` | Создать пира |
| DELETE | `/peers/{id}` | Удалить пира |
| GET | `/peers/{id}/config` | Скачать .conf файл |
| POST | `/peers/keenetic/{id}` | Настроить VPN на роутере Keenetic |
| POST | `/peers/keenetic-dns/{id}` | Настроить DoT-серверы |
| POST | `/peers/keenetic-dns-routes/{id}` | Включить/выключить DNS-маршрутизацию |
| POST | `/peers/keenetic-components/{id}` | Установить компоненты роутера |
| POST | `/components/apply` | Установить компоненты (альтернативный endpoint) |
| GET | `/components/apply/status` | Статус установки компонентов |
| GET | `/dns/routes` | Список DNS-маршрутов |
| POST | `/dns/routes/create` | Добавить DNS-маршрут |
| POST | `/dns/routes/update` | Обновить DNS-маршрут |
| POST | `/dns/routes/delete` | Удалить DNS-маршрут |
| POST | `/dns/routes/apply` | Применить DNS-маршруты к роутерам |
| GET | `/dns/apply/status` | Статус применения DNS-маршрутов |
| GET | `/presets/dns-routes` | Пресеты DNS-маршрутов |

## Лицензия

MIT
