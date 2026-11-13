package main

import (
	"testing"
)

func TestDigitsOnly(t *testing.T) {
	tests := []struct{ in, want string }{
		{"+7 (999) 123-45-67", "79991234567"},
		{"8-999-123-45-67", "89991234567"},
		{"", ""},
		{"abc", ""},
	}
	for _, tt := range tests {
		if got := digitsOnly(tt.in); got != tt.want {
			t.Errorf("digitsOnly(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPhonesMatch(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"+79991234567", "89991234567", true},
		{"+7 999 123 45 67", "9991234567", true},
		{"89991234567", "89991234568", false},
		{"+79991234567", "+380991234567", false},
		{"12345", "12345", false}, // короче 10 цифр — не сравниваем
		{"", "", false},
	}
	for _, tt := range tests {
		if got := phonesMatch(tt.a, tt.b); got != tt.want {
			t.Errorf("phonesMatch(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFindPeerByPhone(t *testing.T) {
	peers := []Peer{
		{ID: "1", Name: "Один", Phone: "+79991234567"},
		{ID: "2", Name: "Два", Phone: ""},
		{ID: "3", Name: "Три", Phone: "8 (912) 345-67-89"},
	}
	tests := []struct {
		phone string
		want  string
	}{
		{"89991234567", "1"},
		{"+7 912 345 67 89", "3"},
		{"+79000000000", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := findPeerByPhone(tt.phone, peers)
		id := ""
		if got != nil {
			id = got.ID
		}
		if id != tt.want {
			t.Errorf("findPeerByPhone(%q) = %q, want %q", tt.phone, id, tt.want)
		}
	}
}

func TestUpsertTelegramUser(t *testing.T) {
	users := &TelegramUsers{}

	u := upsertTelegramUser(users, 100, "ivan", "Иван", "Иванов")
	if len(users.Users) != 1 || u.TGID != 100 || u.MsgCount != 1 {
		t.Fatalf("создание пользователя: %+v", users.Users)
	}
	if u.StartedAt.IsZero() || u.LastSeen.IsZero() {
		t.Error("активность должна фиксироваться")
	}

	u = upsertTelegramUser(users, 100, "ivan2", "Иван", "")
	if len(users.Users) != 1 {
		t.Fatalf("пользователь должен обновляться, а не создаваться: %d", len(users.Users))
	}
	if u.Username != "ivan2" || u.MsgCount != 2 {
		t.Errorf("обновление пользователя: %+v", u)
	}

	upsertTelegramUser(users, 200, "petr", "Пётр", "")
	if len(users.Users) != 2 {
		t.Errorf("ожидалось 2 пользователя: %d", len(users.Users))
	}

	if findTelegramUser(users, 100) == nil || findTelegramUser(users, 999) != nil {
		t.Error("findTelegramUser работает неверно")
	}
}

func TestTelegramUserLinking(t *testing.T) {
	users := &TelegramUsers{}
	u := upsertTelegramUser(users, 100, "ivan", "Иван", "")
	u.Phone = "+79991234567"

	peers := []Peer{{ID: "p1", Name: "Дом", Phone: "89991234567"}}
	if peer := findPeerByPhone(u.Phone, peers); peer == nil || peer.ID != "p1" {
		t.Fatalf("пир по телефону не найден: %+v", peer)
	}

	// Ручная привязка/отвязка
	u.PeerID = "p1"
	u.PeerID = ""
	if u.PeerID != "" {
		t.Error("отвязка не сработала")
	}
}
