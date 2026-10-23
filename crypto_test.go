package main

import (
	"bytes"
	"testing"
)

func withEncryptionKey(t *testing.T, key []byte) {
	t.Helper()
	old := encryptionKey
	t.Cleanup(func() { encryptionKey = old })
	encryptionKey = key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	withEncryptionKey(t, bytes.Repeat([]byte{0x42}, 32))

	const password = "router-secret-123"
	enc := EncryptPassword(password)
	if enc == password {
		t.Fatal("plaintext password must be encrypted")
	}
	dec, ok := DecryptPassword(enc)
	if !ok {
		t.Fatal("decryption must succeed")
	}
	if dec != password {
		t.Errorf("round-trip mismatch: %q != %q", dec, password)
	}
}

func TestEncryptPasswordRandomNonce(t *testing.T) {
	withEncryptionKey(t, bytes.Repeat([]byte{0x42}, 32))

	a := EncryptPassword("same")
	b := EncryptPassword("same")
	if a == b {
		t.Error("two encryptions of the same plaintext must differ (random nonce)")
	}
	if dec, ok := DecryptPassword(b); !ok || dec != "same" {
		t.Errorf("second ciphertext must decrypt: %q %v", dec, ok)
	}
}

func TestDecryptPasswordInvalidInput(t *testing.T) {
	withEncryptionKey(t, bytes.Repeat([]byte{0x42}, 32))

	if _, ok := DecryptPassword("!!!"); ok {
		t.Error("invalid base64 must fail")
	}
	if _, ok := DecryptPassword("AAAA"); ok {
		t.Error("too short payload must fail")
	}

	enc := EncryptPassword("secret")
	// портим последний байт
	raw := []byte(enc)
	if raw[len(raw)-1] == 'A' {
		raw[len(raw)-1] = 'B'
	} else {
		raw[len(raw)-1] = 'A'
	}
	if _, ok := DecryptPassword(string(raw)); ok {
		t.Error("tampered ciphertext must fail authentication")
	}
}

func TestEncryptDecryptWithoutKey(t *testing.T) {
	withEncryptionKey(t, nil)

	if got := EncryptPassword("plain"); got != "plain" {
		t.Errorf("without key password must stay plaintext, got %q", got)
	}
	if got, ok := DecryptPassword("plain"); !ok || got != "plain" {
		t.Errorf("without key DecryptPassword must pass through, got %q %v", got, ok)
	}
}

func TestEncryptEmptyPassword(t *testing.T) {
	withEncryptionKey(t, bytes.Repeat([]byte{0x42}, 32))
	if got := EncryptPassword(""); got != "" {
		t.Errorf("empty plaintext must stay empty, got %q", got)
	}
}
