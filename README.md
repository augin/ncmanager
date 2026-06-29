# ncmanager

Управление WireGuard-пирами на роутерах Keenetic через веб-интерфейс и RCI API.

## Возможности

- Создание/удаление пиров WireGuard
- Автоматическая настройка WireGuard интерфейса на роутере Keenetic через RCI (импорт .conf файла)
- Разделение настройки VPN и DNS: кнопка «Настроить VPN» — только интерфейс, кнопка «Настроить DNS» — только DoT-серверы
- DNS-маршрутизация: доменные и CIDR-правила, применяемые к каждому пиру отдельно
- Библиотека пресетов DNS-маршрутов (75+ категорий)
- Аутентификация по паролю
- Статус WireGuard (handshake, трафик, endpoint)

## Требования

- Сервер с Go 1.21+ (для сборки) или Linux amd64/arm64 (для бинарника)
- Инструменты `wg` и `wg-quick` на сервере
- Права root (для управления WireGuard интерфейсом)
- Роутер Keenetic с RCI (версии поддерживающие RCI JSON API)

## Установка

### Вариант 1: Скачать готовый бинарник

Linux amd64:
```bash
curl -L -o wg-manager https://github.com/augin/ncmanager/releases/download/v0.1.0/wg-manager-linux-amd64
chmod +x wg-manager
```

Linux arm64:
```bash
curl -L -o wg-manager https://github.com/augin/ncmanager/releases/download/v0.1.0/wg-manager-linux-arm64
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
- Порт: `51820`
- Интерфейс: `wg0`
- Файл данных: `data/config.json`
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

1. Откройте `http://<ваш-сервер>:51820` в браузере.
2. Введите пароль (по умолчанию: `admin`).
3. Добавьте первого пира через «Добавить пира».
4. Скачайте `.conf` файл.
5. На роутере Keenetic откройте веб-интерфейс → VPN → WireGuard → Добавить → Импорт конфигурации.
6. Выберите скачанный `.conf` файл.
7. После активации интерфейс `Wireguard1` появится в списке.

## Настройка роутера Keenetic

Для настройки через RCI укажите для пира:
- Домен роутера (`Router Domain`)
- Логин и пароль от веб-интерфейса роутера

Нажмите «Настроить VPN» — ncmanager импортирует конфигурацию через RCI.
Для настройки только DoT-серверов нажмите «Настроить DNS».

## Остановка

```bash
sudo wg-quick down wg0
```

## Структура проекта

```
ncmanager/
├── main.go              # Точка входа, обработчики API
├── router.go            # Общие RCI-хелперы (авторизация, запросы, HTTPS fallback)
├── router_vpn.go        # Настройка VPN на роутере (импорт, добавление/удаление пира)
├── dns_routing.go       # DNS-маршрутизация, Secure DNS, пресеты
├── static/              # Веб-интерфейс
├── templates/
├── presets/
│   └── dns-routes.json
└── data/
    └── config.json      # Хранилище пиров (создаётся автоматически)
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
| POST | `/peers/keenetic` | Настроить VPN на роутере Keenetic |
| POST | `/peers/keenetic-dns` | Настроить только DNS на роутере Keenetic |
| GET | `/dns/routes` | Список DNS-маршрутов |
| POST | `/dns/routes` | Добавить DNS-маршрут |
| DELETE | `/dns/routes/{id}` | Удалить DNS-маршрут |
| POST | `/dns/routes/apply` | Применить DNS-маршруты к пиру |

## Лицензия

MIT
