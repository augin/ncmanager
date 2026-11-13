package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// telegramFile — файл с пользователями телеграм-бота.
const telegramFile = "data/telegram.json"

// telegramAPIBase — базовый URL Telegram Bot API.
const telegramAPIBase = "https://api.telegram.org/bot"

// defaultTelegramWelcome — приветствие бота, если не задано своё.
const defaultTelegramWelcome = "Здравствуйте! Отправьте номер телефона, чтобы привязать аккаунт к адресу."

// TelegramUser — пользователь телеграм-бота, привязанный к пиру.
type TelegramUser struct {
	TGID      int64     `json:"tgId"`
	Username  string    `json:"username,omitempty"`
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Phone     string    `json:"phone,omitempty"`
	PeerID    string    `json:"peerId,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	LinkedAt  time.Time `json:"linkedAt,omitempty"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
	MsgCount  int       `json:"msgCount,omitempty"`
}

// TelegramUsers — список пользователей бота.
type TelegramUsers struct {
	Users []TelegramUser `json:"users"`
}

// tgUsersMu сериализует доступ к data/telegram.json (бот + HTTP-хендлеры).
var tgUsersMu sync.Mutex

func loadTelegramUsers() (*TelegramUsers, error) {
	data, err := os.ReadFile(telegramFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &TelegramUsers{Users: []TelegramUser{}}, nil
		}
		return nil, err
	}
	var users TelegramUsers
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	if users.Users == nil {
		users.Users = []TelegramUser{}
	}
	return &users, nil
}

func saveTelegramUsers(users *TelegramUsers) error {
	_ = os.MkdirAll("data", 0700)
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(telegramFile, data)
}

// digitsOnly оставляет в номере только цифры.
func digitsOnly(phone string) string {
	var b strings.Builder
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// phonesMatch сравнивает номера по последним 10 цифрам: так
// +79991234567 и 89991234567 считаются одним номером, а номера из разных
// стран с общим хвостом не смешиваются.
func phonesMatch(a, b string) bool {
	const tail = 10
	da, db := digitsOnly(a), digitsOnly(b)
	if len(da) < tail || len(db) < tail {
		return false
	}
	return da[len(da)-tail:] == db[len(db)-tail:]
}

// findPeerByPhone находит пир с совпадающим номером телефона.
func findPeerByPhone(phone string, peers []Peer) *Peer {
	for i := range peers {
		if strings.TrimSpace(peers[i].Phone) != "" && phonesMatch(phone, peers[i].Phone) {
			return &peers[i]
		}
	}
	return nil
}

// upsertTelegramUser обновляет данные пользователя по TG ID (создаёт при
// отсутствии) и фиксирует активность.
func upsertTelegramUser(users *TelegramUsers, tgID int64, username, firstName, lastName string) *TelegramUser {
	for i := range users.Users {
		if users.Users[i].TGID == tgID {
			u := &users.Users[i]
			u.Username = username
			u.FirstName = firstName
			u.LastName = lastName
			u.LastSeen = time.Now()
			u.MsgCount++
			return u
		}
	}
	users.Users = append(users.Users, TelegramUser{
		TGID:      tgID,
		Username:  username,
		FirstName: firstName,
		LastName:  lastName,
		StartedAt: time.Now(),
		LastSeen:  time.Now(),
		MsgCount:  1,
	})
	return &users.Users[len(users.Users)-1]
}

// findTelegramUser ищет пользователя по TG ID.
func findTelegramUser(users *TelegramUsers, tgID int64) *TelegramUser {
	for i := range users.Users {
		if users.Users[i].TGID == tgID {
			return &users.Users[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Telegram Bot API (минимальный клиент)

// tgAPI — клиент Telegram Bot API.
type tgAPI struct {
	token string
	http  *http.Client
}

func newTGAPI(token string) *tgAPI {
	// Таймаут больше long-poll таймаута getUpdates (30с).
	return &tgAPI{token: strings.TrimSpace(token), http: &http.Client{Timeout: 90 * time.Second}}
}

func (t *tgAPI) call(ctx context.Context, method string, params, out interface{}) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramAPIBase+t.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("Telegram API: неожиданный ответ (HTTP %d)", resp.StatusCode)
	}
	if !env.OK {
		if env.Description == "" {
			env.Description = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("Telegram API: %s", env.Description)
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return err
		}
	}
	return nil
}

// tgUpdate — входящее обновление (только текст и контакт — больше не нужно).
type tgUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		From *struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"from"`
		Text    string `json:"text"`
		Contact *struct {
			PhoneNumber string `json:"phone_number"`
			UserID      int64  `json:"user_id"`
		} `json:"contact"`
	} `json:"message"`
}

// sendMessage отправляет сообщение; withKeyboard — с кнопкой отправки
// номера телефона.
func (t *tgAPI) sendMessage(ctx context.Context, chatID int64, text string, withKeyboard bool) error {
	params := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}
	if withKeyboard {
		params["reply_markup"] = map[string]interface{}{
			"keyboard": [][]map[string]interface{}{
				{{"text": "📱 Отправить мой номер", "request_contact": true}},
			},
			"resize_keyboard":   true,
			"one_time_keyboard": true,
		}
	}
	return t.call(ctx, "sendMessage", params, nil)
}

// ---------------------------------------------------------------------------
// Рантайм бота

// telegramBotState — состояние бота для веб-интерфейса.
type telegramBotState struct {
	Running    bool   `json:"running"`
	BotName    string `json:"botName"`
	LastError  string `json:"lastError"`
	LastUpdate string `json:"lastUpdate"`
}

// telegramBot управляет фоновым циклом long-polling.
type telegramBot struct {
	mu         sync.Mutex
	running    bool
	botName    string
	lastError  string
	lastUpdate time.Time
	cancel     context.CancelFunc
}

var tgBot = &telegramBot{}

func (b *telegramBot) snapshot() telegramBotState {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := telegramBotState{Running: b.running, BotName: b.botName, LastError: b.lastError}
	if !b.lastUpdate.IsZero() {
		st.LastUpdate = b.lastUpdate.Format(time.RFC3339)
	}
	return st
}

func (b *telegramBot) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastError = err.Error()
	log.Printf("telegram: %v", err)
}

// initTelegram запускает бота по сохранённой конфигурации.
func initTelegram() {
	go applyTelegramFromConfig()
}

// applyTelegramFromConfig перезапускает бота в соответствии с конфигом:
// включён — работает, выключен — остановлен.
func applyTelegramFromConfig() {
	cfg, err := loadConfig(dataFile)
	if err != nil || cfg == nil {
		return
	}

	tgBot.mu.Lock()
	if tgBot.cancel != nil {
		tgBot.cancel()
		tgBot.cancel = nil
	}
	tgBot.mu.Unlock()

	if !cfg.TelegramEnabled || strings.TrimSpace(cfg.TelegramToken) == "" {
		tgBot.mu.Lock()
		tgBot.running = false
		tgBot.mu.Unlock()
		log.Printf("telegram: бот выключен")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	tgBot.mu.Lock()
	tgBot.cancel = cancel
	tgBot.lastError = ""
	tgBot.mu.Unlock()
	go runTelegramBot(ctx, cfg)
}

// runTelegramBot — цикл long-polling: читает обновления и обрабатывает их.
func runTelegramBot(ctx context.Context, cfg *Config) {
	defer func() {
		tgBot.mu.Lock()
		tgBot.running = false
		tgBot.mu.Unlock()
	}()

	api := newTGAPI(cfg.TelegramToken)

	me, err := tgGetMe(ctx, api)
	if err != nil {
		tgBot.setErr(fmt.Errorf("не удалось подключиться к боту: %w", err))
		return
	}
	tgBot.mu.Lock()
	tgBot.running = true
	tgBot.botName = me
	tgBot.lastError = ""
	tgBot.mu.Unlock()
	log.Printf("telegram: бот %s запущен", me)

	var offset int64
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := tgGetUpdates(ctx, api, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			tgBot.setErr(err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			handleTelegramUpdate(ctx, api, cfg, u)
		}
		tgBot.mu.Lock()
		tgBot.lastUpdate = time.Now()
		tgBot.mu.Unlock()
	}
}

// tgGetMe возвращает имя бота (@username).
func tgGetMe(ctx context.Context, api *tgAPI) (string, error) {
	var me struct {
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	}
	if err := api.call(ctx, "getMe", map[string]interface{}{}, &me); err != nil {
		return "", err
	}
	if me.Username != "" {
		return "@" + me.Username, nil
	}
	return me.FirstName, nil
}

// tgGetUpdates читает пачку обновлений (long-polling).
func tgGetUpdates(ctx context.Context, api *tgAPI, offset int64) ([]tgUpdate, error) {
	var updates []tgUpdate
	params := map[string]interface{}{
		"offset":          offset,
		"timeout":         25,
		"allowed_updates": []string{"message"},
	}
	if err := api.call(ctx, "getUpdates", params, &updates); err != nil {
		return nil, err
	}
	return updates, nil
}

// handleTelegramUpdate обрабатывает одно обновление: учитывает активность,
// привязывает пользователя к пиру по номеру телефона.
func handleTelegramUpdate(ctx context.Context, api *tgAPI, cfg *Config, u tgUpdate) {
	msg := u.Message
	if msg == nil || msg.From == nil {
		return
	}
	from := msg.From

	tgUsersMu.Lock()
	users, err := loadTelegramUsers()
	if err != nil {
		tgUsersMu.Unlock()
		tgBot.setErr(fmt.Errorf("чтение пользователей: %w", err))
		return
	}
	user := upsertTelegramUser(users, from.ID, from.Username, from.FirstName, from.LastName)
	chatID := msg.Chat.ID

	var reply string
	switch {
	case msg.Contact != nil:
		user.Phone = strings.TrimSpace(msg.Contact.PhoneNumber)
		peersCfg, perr := loadPeers()
		if perr != nil {
			peersCfg = &PeersConfig{}
		}
		if peer := findPeerByPhone(user.Phone, peersCfg.Peers); peer != nil {
			user.PeerID = peer.ID
			user.LinkedAt = time.Now()
			reply = fmt.Sprintf("✅ Номер %s привязан к адресу «%s».", user.Phone, peer.Name)
		} else {
			user.PeerID = ""
			reply = fmt.Sprintf("⚠️ Адрес с номером %s не найден. Добавьте номер к нужному адресу и отправьте контакт ещё раз.", user.Phone)
		}
	case msg.Text == "/start" || msg.Text == "/help" || msg.Text == "":
		if user.StartedAt.IsZero() {
			user.StartedAt = time.Now()
		}
		if user.PeerID != "" {
			reply = fmt.Sprintf("Вы привязаны к адресу «%s».", tgPeerName(user.PeerID))
		} else {
			reply = cfg.TelegramWelcome
			if strings.TrimSpace(reply) == "" {
				reply = defaultTelegramWelcome
			}
		}
	default:
		if user.PeerID != "" {
			reply = fmt.Sprintf("Вы привязаны к адресу «%s».", tgPeerName(user.PeerID))
		} else {
			reply = defaultTelegramWelcome
		}
	}
	if err := saveTelegramUsers(users); err != nil {
		tgBot.setErr(fmt.Errorf("сохранение пользователей: %w", err))
	}
	tgUsersMu.Unlock()

	withKeyboard := msg.Contact == nil && user.PeerID == ""
	if err := api.sendMessage(ctx, chatID, reply, withKeyboard); err != nil {
		tgBot.setErr(fmt.Errorf("ответ пользователю %d: %w", chatID, err))
	}
}

// tgPeerName возвращает имя пира по ID (или пустую строку).
func tgPeerName(peerID string) string {
	if peerID == "" {
		return ""
	}
	peersCfg, err := loadPeers()
	if err != nil {
		return ""
	}
	for _, p := range peersCfg.Peers {
		if p.ID == peerID {
			return p.Name
		}
	}
	return ""
}
