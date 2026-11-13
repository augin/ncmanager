package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestServeIndexWithoutAuth проверяет, что до авторизации отдаётся только
// минимальная страница входа без структуры приложения.
func TestServeIndexWithoutAuthShowsMinimalPage(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		serveIndex(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("код = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `id="p"`) {
			t.Error("страница входа не содержит поле пароля")
		}
		for _, leak := range []string{
			"tab-settings", "app.js", "style.css", "Пиры", "Настройки",
			"wgPort", "peers", "Cloudflare", "Бэкап",
		} {
			if strings.Contains(body, leak) {
				t.Errorf("страница входа раскрывает %q", leak)
			}
		}
	})
}

// TestServeIndexWithCookie проверяет выдачу полного интерфейса по куке.
func TestServeIndexWithCookieServesApp(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		token := generateToken("admin", currentPasswordHash(), time.Hour)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		serveIndex(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("код = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "tab-settings") || !strings.Contains(body, "static/js/app.js") {
			t.Error("авторизованному запросу не отдан полный интерфейс")
		}
	})
}

// TestServeIndexTokenQuery проверяет перенос токена из адресной строки в куку.
func TestServeIndexTokenQuerySetsCookie(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		token := generateToken("admin", currentPasswordHash(), time.Hour)
		req := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
		rec := httptest.NewRecorder()
		serveIndex(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("код = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("Location = %q, want /", loc)
		}
		var found bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value == token {
				found = true
				if !c.HttpOnly {
					t.Error("кука сессии должна быть HttpOnly")
				}
			}
		}
		if !found {
			t.Error("кука сессии не установлена")
		}
	})
}

// TestServeIndexInvalidTokenQuery проверяет, что невалидный токен не
// попадает в куку.
func TestServeIndexInvalidTokenQueryNoCookie(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		req := httptest.NewRequest(http.MethodGet, "/?token=bad.token", nil)
		rec := httptest.NewRecorder()
		serveIndex(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("код = %d, want 302", rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				t.Error("невалидный токен не должен попадать в куку")
			}
		}
	})
}

// TestStaticAuth проверяет, что статика недоступна без авторизации.
func TestStaticAuth(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		marker := "STATIC-CONTENT"
		handler := staticAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(marker))
		}))

		req := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("без авторизации код = %d, want 404", rec.Code)
		}

		token := generateToken("admin", currentPasswordHash(), time.Hour)
		req = httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), marker) {
			t.Errorf("с авторизацией код = %d, тело = %q", rec.Code, rec.Body.String())
		}
	})
}

// TestLoginSetsSessionCookie проверяет установку куки при входе и
// её удаление при выходе.
func TestLoginAndLogoutSessionCookie(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"secret"}`))
		rec := httptest.NewRecorder()
		loginHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login код = %d, want 200", rec.Code)
		}
		var token string
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName {
				token = c.Value
				if !c.HttpOnly {
					t.Error("кука сессии должна быть HttpOnly")
				}
				if c.SameSite != http.SameSiteStrictMode {
					t.Error("кука сессии должна быть SameSite=Strict")
				}
			}
		}
		if token == "" || !validateToken(token) {
			t.Fatal("кука сессии не содержит валидный токен")
		}

		req = httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		rec = httptest.NewRecorder()
		logoutHandler(rec, req)
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Error("logout не удаляет куку сессии")
		}
	})
}

// TestVersionRequiresAuth проверяет, что /api/version закрыт авторизацией.
func TestVersionRequiresAuth(t *testing.T) {
	withAuthState(t, sha256String("secret"), 0, time.Time{}, []byte("test-secret"), func() {
		handler := withAuth((&Server{}).getVersion)

		req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("без авторизации код = %d, want 401", rec.Code)
		}

		token := generateToken("admin", currentPasswordHash(), time.Hour)
		req = httptest.NewRequest(http.MethodGet, "/api/version", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("с авторизацией код = %d, want 200", rec.Code)
		}
	})
}
