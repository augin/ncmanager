package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authState — состояние аутентификации, защищённое от гонок мьютексом.
// Пароль может быть сменён в рантайме через changePasswordHandler, поэтому
// все чтения/записи идут только через аксессоры ниже.
var authState = struct {
	mu           sync.RWMutex
	passwordHash string
	attempts     int
	blockedUntil time.Time
	secret       []byte
}{}

func currentPasswordHash() string {
	authState.mu.RLock()
	defer authState.mu.RUnlock()
	return authState.passwordHash
}

func setPasswordHash(hash string) {
	authState.mu.Lock()
	authState.passwordHash = hash
	authState.mu.Unlock()
}

func currentAuthSecret() []byte {
	authState.mu.RLock()
	defer authState.mu.RUnlock()
	return authState.secret
}

func setAuthSecret(secret []byte) {
	authState.mu.Lock()
	authState.secret = secret
	authState.mu.Unlock()
}

// authAttempts возвращает текущий счётчик неудачных попыток входа.
func authAttempts() int {
	authState.mu.RLock()
	defer authState.mu.RUnlock()
	return authState.attempts
}

// authBlockedUntil возвращает дедлайн блокировки входа.
func authBlockedUntil() time.Time {
	authState.mu.RLock()
	defer authState.mu.RUnlock()
	return authState.blockedUntil
}

// setAuthState задаёт счётчик попыток и дедлайн блокировки (используется
// при восстановлении состояния из файлов и в тестах).
func setAuthAttempts(blockedUntil time.Time, attempts int) {
	authState.mu.Lock()
	authState.blockedUntil = blockedUntil
	authState.attempts = attempts
	authState.mu.Unlock()
}

func initAuth() {
	if b, err := os.ReadFile(authHashFile); err == nil {
		hash := strings.TrimSpace(string(b))
		setPasswordHash(hash)
		log.Printf("AUTH INIT: loaded hash from file, len=%d hash_prefix=%s", len(hash), hash[:min(8, len(hash))])
	} else if p, ok := os.LookupEnv("WG_MANAGER_PASSWORD"); ok {
		hash := sha256String(p)
		setPasswordHash(hash)
		_ = os.MkdirAll("data", 0700)
		_ = os.WriteFile(authHashFile, []byte(hash), 0600)
		log.Printf("AUTH INIT: using env password hash len=%d", len(hash))
	} else {
		hash := sha256String("admin")
		setPasswordHash(hash)
		_ = os.MkdirAll("data", 0700)
		_ = os.WriteFile(authHashFile, []byte(hash), 0600)
		log.Printf("AUTH INIT: using default admin hash len=%d hash_prefix=%s", len(hash), hash[:min(8, len(hash))])
	}
}

func initAuthSecret() {
	path := authSecretFile
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		setAuthSecret(b)
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("failed to generate auth secret: %v", err)
	}
	setAuthSecret(secret)
	_ = os.MkdirAll("data", 0700)
	_ = os.WriteFile(path, secret, 0600)
}

func generateToken(user string, passwordHash string, ttl time.Duration) string {
	expiry := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s|%s|%d", user, passwordHash, expiry)
	sig := hmac.New(sha256.New, currentAuthSecret())
	sig.Write([]byte(payload))
	return base64.URLEncoding.EncodeToString([]byte(payload)) + "." + base64.URLEncoding.EncodeToString(sig.Sum(nil))
}

func validateToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		log.Printf("TOKEN VALIDATE: bad format, parts=%d", len(parts))
		return false
	}
	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Printf("TOKEN VALIDATE: bad payload base64")
		return false
	}
	expectedSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("TOKEN VALIDATE: bad sig base64")
		return false
	}
	payload := string(payloadBytes)
	sig := hmac.New(sha256.New, currentAuthSecret())
	sig.Write([]byte(payload))
	if !hmac.Equal(sig.Sum(nil), expectedSig) {
		log.Printf("TOKEN VALIDATE: bad signature")
		return false
	}
	segments := strings.Split(payload, "|")
	if len(segments) != 3 {
		log.Printf("TOKEN VALIDATE: bad segments=%d", len(segments))
		return false
	}
	if segments[1] != currentPasswordHash() {
		log.Printf("TOKEN VALIDATE: password hash mismatch")
		return false
	}
	expiry, _ := strconv.ParseInt(segments[2], 10, 64)
	if time.Now().After(time.Unix(expiry, 0)) {
		log.Printf("TOKEN VALIDATE: expired at %v", time.Unix(expiry, 0))
		return false
	}
	return true
}

func sha256String(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// checkPassword проверяет пароль и обновляет счётчик неудачных попыток.
// После 5 неудач подряд вход блокируется на 5 минут.
func checkPassword(pw string) bool {
	hash := sha256String(pw)

	authState.mu.Lock()
	defer authState.mu.Unlock()

	if time.Now().Before(authState.blockedUntil) {
		return false
	}
	if hash == authState.passwordHash {
		authState.attempts = 0
		return true
	}
	authState.attempts++
	if authState.attempts >= 5 {
		authState.blockedUntil = time.Now().Add(5 * time.Minute)
	}
	return false
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token == "" {
		token = r.Header.Get("X-Session-Token")
	}
	if token != "" && validateToken(token) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	return false
}

func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		handler(w, r)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	log.Printf("LOGIN ATTEMPT")
	if checkPassword(req.Password) {
		hash := currentPasswordHash()
		token := generateToken("admin", hash, 168*time.Hour)
		resp := map[string]string{"status": "ok", "token": token}
		if hash == sha256String("admin") {
			resp["requirePasswordChange"] = "true"
		}
		log.Printf("LOGIN SUCCESS: token prefix=%s", token[:8])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	} else {
		log.Printf("LOGIN FAILED")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid password"})
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "password cannot be empty"})
		return
	}
	hash := sha256String(req.NewPassword)
	setPasswordHash(hash)
	_ = os.MkdirAll("data", 0700)
	_ = os.WriteFile(authHashFile, []byte(hash), 0600)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
