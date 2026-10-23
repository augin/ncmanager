package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withAuthState подменяет глобальное состояние аутентификации на время fn
// и восстанавливает исходное.
func withAuthState(t *testing.T, hash string, attempts int, blockedUntil time.Time, secret []byte, fn func()) {
	t.Helper()

	origHash := currentPasswordHash()
	origAttempts := authAttempts()
	origBlocked := authBlockedUntil()
	origSecret := currentAuthSecret()
	t.Cleanup(func() {
		setPasswordHash(origHash)
		setAuthAttempts(origBlocked, origAttempts)
		setAuthSecret(origSecret)
	})

	setPasswordHash(hash)
	setAuthAttempts(blockedUntil, attempts)
	setAuthSecret(secret)
	fn()
}

func TestTokenRoundTrip(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		token := generateToken("admin", currentPasswordHash(), time.Hour)
		if token == "" {
			t.Fatal("generateToken вернул пустую строку")
		}
		if !validateToken(token) {
			t.Error("валидный токен не прошёл проверку")
		}
	})
}

func TestValidateTokenRejected(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		if validateToken("") {
			t.Error("пустой токен прошёл проверку")
		}
		if validateToken("deadbeef") {
			t.Error("мусорный токен прошёл проверку")
		}

		// Чужой секрет подписи.
		good := generateToken("admin", currentPasswordHash(), time.Hour)
		setAuthSecret([]byte("other-secret"))
		if validateToken(good) {
			t.Error("токен, подписанный другим секретом, прошёл проверку")
		}
		setAuthSecret([]byte("test-secret"))

		// Смена пароля инвалидирует старые токены.
		setPasswordHash(sha256String("new-secret"))
		if validateToken(good) {
			t.Error("токен со старым хэшем пароля прошёл проверку")
		}
		setPasswordHash(sha256String("secret"))

		// Истёкший токен.
		expired := generateToken("admin", currentPasswordHash(), -time.Hour)
		if validateToken(expired) {
			t.Error("просроченный токен прошёл проверку")
		}
	})
}

func TestValidateTokenNeverPanics(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("s"), func() {
		cases := []string{"", "x", "xx", "0123456789abcdef", strings.Repeat("a", 64), strings.Repeat("a", 64) + "." + strings.Repeat("b", 64)}
		for _, tok := range cases {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("validateToken(%q) паниковал: %v", tok, r)
					}
				}()
				validateToken(tok)
			}()
		}
	})
}

// generateToken детерминирован внутри одной секунды: срок годности
// записывается с точностью до секунды, поэтому два вызова в одну секунду
// дают одинаковый токен. Разные сроки — разные токены.
func TestGenerateTokenUniqueness(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		a := generateToken("admin", currentPasswordHash(), time.Hour)
		b := generateToken("admin", currentPasswordHash(), 2*time.Hour)
		if a == b {
			t.Error("токены с разным сроком годности совпали")
		}
	})
}

func TestCheckPasswordRateLimit(t *testing.T) {
	withAuthState(t, sha256String("correct"), 0, time.Time{}, []byte("s"), func() {
		if !checkPassword("correct") {
			t.Fatal("верный пароль отвергнут")
		}
		if got := authAttempts(); got != 0 {
			t.Errorf("после успешного входа счётчик = %d, ожидался 0", got)
		}
		for i := 1; i <= 4; i++ {
			if checkPassword("wrong") {
				t.Fatalf("неверный пароль принят на попытке %d", i)
			}
			if got := authAttempts(); got != i {
				t.Errorf("после %d неудач счётчик = %d", i, got)
			}
		}
		if checkPassword("wrong") {
			t.Error("5-я неудачная попытка не заблокирована")
		}
		if authBlockedUntil().IsZero() {
			t.Error("после 5 неудач дедлайн блокировки не выставлен")
		}
		// Даже верный пароль отвергается в период блокировки.
		if checkPassword("correct") {
			t.Error("пароль принят во время блокировки")
		}
	})
}

func TestChangePasswordHandlerValidation(t *testing.T) {
	inTempData(t)

	// Пустой пароль отклоняется.
	withAuthState(t, sha256String("old"), 0, time.Time{}, []byte("s"), func() {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", strings.NewReader(`{"newPassword":"  "}`))
		rec := httptest.NewRecorder()
		changePasswordHandler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("пустой пароль: код %d, ожидался 400", rec.Code)
		}
	})

	// Успешная смена обновляет хэш.
	withAuthState(t, sha256String("old"), 3, time.Now(), []byte("s"), func() {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", strings.NewReader(`{"newPassword":"fresh-pass"}`))
		rec := httptest.NewRecorder()
		changePasswordHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("смена пароля: код %d, ожидался 200 (тело: %s)", rec.Code, rec.Body.String())
		}
		if got := currentPasswordHash(); got != sha256String("fresh-pass") {
			t.Error("хэш пароля не обновился")
		}
		if !checkPassword("fresh-pass") {
			t.Error("новый пароль не принимается")
		}
	})

	// GET отклоняется.
	withAuthState(t, sha256String("old"), 0, time.Time{}, []byte("s"), func() {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/change-password", nil)
		rec := httptest.NewRecorder()
		changePasswordHandler(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET: код %d, ожидался 405", rec.Code)
		}
	})
}
