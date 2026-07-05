package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
)

var encryptionKey []byte

func InitEncryptionKey() {
	path := "data/.key"
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		encryptionKey = b[:32]
		return
	}
	encryptionKey = make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		log.Fatalf("failed to generate encryption key: %v", err)
	}
	_ = os.MkdirAll("data", 0700)
	_ = os.WriteFile(path, encryptionKey, 0600)
}

func EncryptPassword(plaintext string) string {
	if len(encryptionKey) == 0 || plaintext == "" {
		return plaintext
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return plaintext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plaintext
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plaintext
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func DecryptPassword(ciphertext string) (string, bool) {
	if len(encryptionKey) == 0 || ciphertext == "" {
		return ciphertext, true
	}
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return ciphertext, false
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return ciphertext, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext, false
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ciphertext, false
	}
	nonce, cipherBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return ciphertext, false
	}
	return string(plaintext), true
}
