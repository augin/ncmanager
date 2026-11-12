package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const appVersion = "1.18.0"

const dataFile = "data/config.json"

const peersFile = "data/peers.json"

const dnsRoutesFile = "data/dns-routes.json"

const wgConfigFile = "/etc/wireguard/wg0.conf"

const logDir = "/var/log/ncmanager"

const (
	serverPrivateKeyFile = "data/server_private.key"
	authHashFile         = "data/.auth"
	authSecretFile       = "data/.secret"
	encryptionKeyFile    = "data/.key"
	presetsFile          = "presets/dns-routes.json"
	amneziaConfDir       = "/etc/amnezia/amneziawg"
	wireguardConfDir     = "/etc/wireguard"
)

// amneziaConfPath возвращает путь к конфигу AmneziaWG по имени интерфейса.

// amneziaConfPath возвращает путь к конфигу AmneziaWG по имени интерфейса.
func amneziaConfPath(name string) string {
	return filepath.Join(amneziaConfDir, name+".conf")
}

var errPeerNotFound = errors.New("peer not found")

// peerConfigError пишет стандартные HTTP-ответы для ошибок поиска пира.

// peerConfigError пишет стандартные HTTP-ответы для ошибок поиска пира.
func peerConfigError(w http.ResponseWriter, err error) {
	if errors.Is(err, errPeerNotFound) {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// requirePost отвечает 405 на неподходящий метод. false — метод подходит.

// requirePost отвечает 405 на неподходящий метод. false — метод подходит.
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// decodeJSONBody декодирует JSON-тело запроса; при ошибке пишет 400
// и возвращает false.

// decodeJSONBody декодирует JSON-тело запроса; при ошибке пишет 400
// и возвращает false.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}

// peerIDFromPath извлекает ID пира из /api/peers/<id>/...; при отсутствии
// ID пишет 400 и возвращает ok=false.

// peerIDFromPath извлекает ID пира из /api/peers/<id>/...; при отсутствии
// ID пишет 400 и возвращает ok=false.
func peerIDFromPath(w http.ResponseWriter, r *http.Request) (id string, ok bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "peer id required", http.StatusBadRequest)
		return "", false
	}
	return parts[3], true
}

// findPeerIndex возвращает индекс пира по ID или -1.

// findPeerIndex возвращает индекс пира по ID или -1.
func findPeerIndex(peers []Peer, id string) int {
	for i := range peers {
		if peers[i].ID == id {
			return i
		}
	}
	return -1
}

// findPeer возвращает указатель на пир по ID или nil.

// findPeer возвращает указатель на пир по ID или nil.
func findPeer(peers []Peer, id string) *Peer {
	if i := findPeerIndex(peers, id); i >= 0 {
		return &peers[i]
	}
	return nil
}

// resolveServerPublicKey возвращает публичный ключ сервера: сначала из
// работающего интерфейса, затем из сохранённого приватного ключа.

// resolveServerPublicKey возвращает публичный ключ сервера: сначала из
// работающего интерфейса, затем из сохранённого приватного ключа.
func resolveServerPublicKey() string {
	if pub := getActualServerPublicKey(); pub != "" {
		return pub
	}
	priv, _ := loadPrivateKey(serverPrivateKeyFile)
	pub, _ := getPublicKeyFromPrivate(priv)
	return pub
}

func initLogger() {
	os.MkdirAll("data", 0700)
	f, err := os.OpenFile(filepath.Join(logDir, "ncmanager.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log file: %v", err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
}

func execWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func getCIDRPrefix(ipnet *net.IPNet) int {
	ones, _ := ipnet.Mask.Size()
	return ones
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	http.ServeFile(w, r, "templates/index.html")
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func resolveEndpoint(endpoint string) string {
	if endpoint == "" || endpoint == "AUTO" {
		return getPublicIP()
	}
	if net.ParseIP(endpoint) != nil {
		return endpoint
	}
	return endpoint
}

func detectDefaultWan() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.To4() != nil {
				return iface.Name
			}
		}
	}
	return "eth0"
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if tr, ok := cyrTranslitSlug[unicode.ToLower(r)]; ok {
			b.WriteString(tr)
		} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := b.String()
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	out = strings.Trim(out, "_")
	if out == "" {
		return "peer"
	}
	return out
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func isBase64(s string) bool {
	if s == "" || len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
