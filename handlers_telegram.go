package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// getTelegramConfig отдаёт настройки бота.
func (s *Server) getTelegramConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig(dataFile)
	if err != nil || cfg == nil {
		http.Error(w, "failed to load config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled": cfg.TelegramEnabled,
		"token":   cfg.TelegramToken,
		"welcome": cfg.TelegramWelcome,
	})
}

// saveTelegramConfig сохраняет настройки бота и перезапускает его.
func (s *Server) saveTelegramConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Token   string `json:"token"`
		Welcome string `json:"welcome"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	s.mu.Lock()
	cfg, err := loadConfig(dataFile)
	if err != nil || cfg == nil {
		cfg = &Config{}
	}
	cfg.TelegramEnabled = req.Enabled
	cfg.TelegramToken = strings.TrimSpace(req.Token)
	cfg.TelegramWelcome = strings.TrimSpace(req.Welcome)
	if cfg.TelegramEnabled && cfg.TelegramToken == "" {
		s.mu.Unlock()
		http.Error(w, "токен бота не задан", http.StatusBadRequest)
		return
	}
	if err := saveConfig(dataFile, cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()

	go applyTelegramFromConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// getTelegramStatus отдаёт состояние бота и сводку по пользователям.
func (s *Server) getTelegramStatus(w http.ResponseWriter, r *http.Request) {
	cfg, _ := loadConfig(dataFile)
	st := tgBot.snapshot()
	resp := map[string]any{
		"enabled":    cfg != nil && cfg.TelegramEnabled,
		"running":    st.Running,
		"botName":    st.BotName,
		"lastError":  st.LastError,
		"lastUpdate": st.LastUpdate,
	}
	tgUsersMu.Lock()
	users, err := loadTelegramUsers()
	tgUsersMu.Unlock()
	if err == nil {
		linked := 0
		for _, u := range users.Users {
			if u.PeerID != "" {
				linked++
			}
		}
		resp["userCount"] = len(users.Users)
		resp["linkedCount"] = linked
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// telegramUserInfo — пользователь бота с данными привязанного пира.
type telegramUserInfo struct {
	TGID      int64  `json:"tgId"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	PeerID    string `json:"peerId"`
	PeerName  string `json:"peerName"`
	StartedAt string `json:"startedAt"`
	LinkedAt  string `json:"linkedAt"`
	LastSeen  string `json:"lastSeen"`
	MsgCount  int    `json:"msgCount"`
}

// listTelegramUsers отдаёт пользователей бота с привязкой к пирам.
func (s *Server) listTelegramUsers(w http.ResponseWriter, r *http.Request) {
	tgUsersMu.Lock()
	users, err := loadTelegramUsers()
	tgUsersMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	peersCfg, _ := loadPeers()
	peerNames := map[string]string{}
	if peersCfg != nil {
		for _, p := range peersCfg.Peers {
			peerNames[p.ID] = p.Name
		}
	}

	list := make([]telegramUserInfo, 0, len(users.Users))
	for _, u := range users.Users {
		info := telegramUserInfo{
			TGID:     u.TGID,
			Username: u.Username,
			Name:     strings.TrimSpace(u.FirstName + " " + u.LastName),
			Phone:    u.Phone,
			PeerID:   u.PeerID,
			PeerName: peerNames[u.PeerID],
			MsgCount: u.MsgCount,
		}
		if !u.StartedAt.IsZero() {
			info.StartedAt = u.StartedAt.Format(time.RFC3339)
		}
		if !u.LinkedAt.IsZero() {
			info.LinkedAt = u.LinkedAt.Format(time.RFC3339)
		}
		if !u.LastSeen.IsZero() {
			info.LastSeen = u.LastSeen.Format(time.RFC3339)
		}
		list = append(list, info)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// updateTelegramUser привязывает/отвязывает пользователя к пиру вручную.
func (s *Server) updateTelegramUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TGID   int64  `json:"tgId"`
		PeerID string `json:"peerId"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	tgUsersMu.Lock()
	defer tgUsersMu.Unlock()
	users, err := loadTelegramUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user := findTelegramUser(users, req.TGID)
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if req.PeerID == "" {
		user.PeerID = ""
		user.LinkedAt = time.Time{}
	} else {
		peersCfg, _ := loadPeers()
		found := false
		if peersCfg != nil {
			for _, p := range peersCfg.Peers {
				if p.ID == req.PeerID {
					found = true
					break
				}
			}
		}
		if !found {
			http.Error(w, "peer not found", http.StatusNotFound)
			return
		}
		user.PeerID = req.PeerID
		user.LinkedAt = time.Now()
	}
	if err := saveTelegramUsers(users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// deleteTelegramUser удаляет пользователя из списка бота.
func (s *Server) deleteTelegramUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TGID int64 `json:"tgId"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	tgUsersMu.Lock()
	defer tgUsersMu.Unlock()
	users, err := loadTelegramUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filtered := users.Users[:0]
	for _, u := range users.Users {
		if u.TGID != req.TGID {
			filtered = append(filtered, u)
		}
	}
	if len(filtered) == len(users.Users) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	users.Users = filtered
	if err := saveTelegramUsers(users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
