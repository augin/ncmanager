# ncmanager

Управление WireGuard-пирами на роутерах Keenetic через веб-интерфейс и RCI API.

## Возможности

- Создание/удаление пиров WireGuard
- Автоматическая настройка WireGuard интерфейса на роутере Keenetic через RCI (импорт .conf файла)
- Установка компонентов роутера (wireguard, dns-tls) — пакетная установка с одной перезагрузкой
- Настройка DoT-серверов (Quad9, Cloudflare, Яндекс с доменной фильтрацией)
- DNS-маршрутизация: доменные и CIDR-правила, применяемые к каждому пиру отдельно
- Библиотека пресетов DNS-маршрутов (75+ категорий)
- Резервное копирование и восстановление (вкладка «Бэкап»)
- Аутентификация по паролю
- Статус WireGuard (handshake, трафик, endpoint)
- Автозапуск AmneziaWG интерфейсов после импорта и восстановления
- Транслитерация кириллицы в именах пиров для VPN-интерфейсов на роутере
- Корректное применение новой подсети сервера (перезапись wg0.conf + принудительный перезапуск интерфейса)

## Требования

- Linux amd64 (Debian/Ubuntu)
- Права root (устанавливаются через deb)
- Роутер Keenetic с RCI (KeeneticOS 5.x+, поддержка DNS-over-TLS и WireGuard)

## Установка

### Deb-пакет (рекомендуется)

Скачайте последний `.deb` файл из [Releases](https://github.com/augin/ncmanager/releases) и установите:

```bash
sudo dpkg -i ncmanager_<version>.deb
sudo apt-get install -f
```

IP forwarding включится автоматически, сервис `ncmanager` запустится сам.

## Запуск

Сервис уже запущен после установки `.deb`.  
Для ручного управления:

```bash
sudo systemctl restart ncmanager
```

По умолчанию:
- Веб-интерфейс: `8080`
- WireGuard порт: `51820`
- Интерфейс: `wg0`
- Рабочая директория: `/var/lib/ncmanager`
- Глобальные настройки: `/var/lib/ncmanager/data/config.json`
- Пиры и DNS-маршруты: `/var/lib/ncmanager/data/peers.json`
- Конфигурация WG: `/etc/wireguard/wg0.conf`

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
| **Настроить DNS-маршрутизацию** | Создаёт списки доменных имён и правила маршрутизации на роутере. |
| **Скачать бэкап** | Создаёт ZIP-архив с настройками, пирами, ключами, конфигами WireGuard и AmneziaWG. |
| **Восстановить из файла** | Восстанавливает состояние из ZIP-бэкапа: настройки, пиры, конфиги интерфейсов, автозапуск. |

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

## Резервное копирование и восстановление

Вкладка «Бэкап» позволяет создать полный архив состояния ncmanager и восстановить его на другом сервере.

### Что попадает в бэкап

- `data/config.json` — глобальные настройки (порт, подсеть, DNS, интерфейс, TLS)
- `data/peers.json` — все пиры с ключами, allowed-ips, router-credentials
- `data/server_private.key` — приватный ключ WireGuard-сервера
- `data/.auth` — хеш пароля администратора
- `data/.secret` — HMAC-секрет для токенов
- `presets/dns-routes.json` — пресеты DNS-маршрутов
- `/etc/wireguard/*` — все файлы конфигурации WireGuard
- `/etc/amnezia/amneziawg/*.conf` — конфиги AmneziaWG интерфейсов

### Восстановление

При восстановлении из .zip:
1. Все перечисленные файлы записываются на свои места
2. `wg0.conf` регенерируется из актуальных настроек и поднимается через `wg-quick`
3. AmneziaWG интерфейсы поднимаются через `awg-quick up` и регистрируются в systemd для автозапуска (`systemctl enable --now awg-quick@<name>`)
4. Интерфейсы, присутствовавшие в бэкапе, будут активны после восстановления

### Примечания

- Бэкап содержит конфиденциальные данные (приватные ключи, пароли). Храните архив в защищённом месте.
- `templates/`, `static/` и `ncmanager.service` в бэкап не попадают — они поставляются с пакетом.
- `/tmp/*` логи и временные файлы в бэкап не попадают.

## Остановка

```bash
sudo wg-quick down wg0
```

## Структура проекта

```
/var/lib/ncmanager/
├── data/
│   ├── config.json        # Глобальные настройки (создаётся автоматически)
│   └── peers.json         # Пиры и DNS-маршруты (создаётся автоматически)
├── presets/
│   └── dns-routes.json    # Пресеты DNS-маршрутов
├── static/                # Веб-интерфейс
├── templates/             # HTML-шаблоны
└── ncmanager.service      # systemd unit

/usr/local/bin/ncmanager   # Бинарник
/etc/wireguard/wg0.conf    # Конфигурация WireGuard
```

## API

Все endpoints кроме `/` и `/api/version` требуют базовую аутентификацию.

| Метод | Endpoint | Описание |
|-------|----------|----------|
| GET | `/api/version` | Версия приложения (публичный) |
| GET | `/api/status` | Статус WireGuard |
| GET | `/api/config` | Текущая конфигурация |
| POST | `/api/config/save` | Сохранить конфигурацию |
| POST | `/api/peers` | Создать пира |
| DELETE | `/api/peers/{id}` | Удалить пира |
| GET | `/api/peers/{id}/config` | Скачать .conf файл |
| POST | `/api/peers/keenetic/{id}` | Настроить VPN на роутере Keenetic |
| POST | `/api/peers/keenetic-dns/{id}` | Настроить DoT-серверы |
| POST | `/api/peers/keenetic-dns-routes/{id}` | Настроить DNS-маршрутизацию |
| POST | `/api/peers/keenetic-components/{id}` | Установить компоненты роутера |
| POST | `/api/components/apply` | Установить компоненты (альтернативный endpoint) |
| GET | `/api/components/apply/status` | Статус установки компонентов |
| GET | `/api/dns/routes` | Список DNS-маршрутов |
| POST | `/api/dns/routes/create` | Добавить DNS-маршрут |
| POST | `/api/dns/routes/update` | Обновить DNS-маршрут |
| POST | `/api/dns/routes/delete` | Удалить DNS-маршрут |
| POST | `/api/dns/routes/apply` | Применить DNS-маршруты к роутерам |
| GET | `/api/dns/apply/status` | Статус применения DNS-маршрутов |
| GET | `/api/presets/dns-routes` | Пресеты DNS-маршрутов |
| POST | `/api/backup/create` | Скачать резервную копию (ZIP) |
| POST | `/api/backup/restore` | Восстановить из резервной копии (ZIP) |

## Изменения в версии 1.3.6

- Добавлена вкладка «Бэкап»: скачивание ZIP-архива и восстановление из него
- Автозапуск AmneziaWG интерфейсов после импорта и восстановления (`systemctl enable --now awg-quick@<name>`)
- Транслитерация кириллицы в именах пиров для VPN-интерфейсов на роутере (вместо `_`)
- Исправлена смена подсети: `wg0.conf` теперь перезаписывается корректно, интерфейс принудительно перезапускается
- При смене подсети автоматически пересчитываются `AllowedIPs` всех существующих пиров
- Убрана проверка CIDR в DNS-маршрутизации на фронтенде

## Лицензия

MIT
