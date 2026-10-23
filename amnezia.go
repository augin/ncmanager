package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var amneziaTrafficBuf = struct {
	mu      sync.RWMutex
	entries map[string]*amneziaTrafficEntry
}{entries: make(map[string]*amneziaTrafficEntry)}

const amneziaMaxTrafficPoints = 3600

func feedAmneziaTraffic(name string, rxBytes int64, txBytes int64) {
	now := time.Now().Unix()
	amneziaTrafficBuf.mu.Lock()
	entry := amneziaTrafficBuf.entries[name]
	if entry == nil {
		entry = &amneziaTrafficEntry{}
		amneziaTrafficBuf.entries[name] = entry
	}
	if len(entry.points) > 0 {
		last := entry.points[len(entry.points)-1]
		dt := now - last.TS
		if dt > 0 {
			entry.points = append(entry.points, amneziaTrafficSnapshot{TS: now, Rx: rxBytes, Tx: txBytes})
		}
	} else {
		entry.points = append(entry.points, amneziaTrafficSnapshot{TS: now, Rx: rxBytes, Tx: txBytes})
	}
	if len(entry.points) > amneziaMaxTrafficPoints {
		entry.points = entry.points[len(entry.points)-amneziaMaxTrafficPoints:]
	}
	amneziaTrafficBuf.mu.Unlock()
}

func getAmneziaTrafficPoints(name string, durationSec int64) ([]amneziaTrafficSnapshot, amneziaTrafficStats) {
	amneziaTrafficBuf.mu.RLock()
	entry, ok := amneziaTrafficBuf.entries[name]
	amneziaTrafficBuf.mu.RUnlock()
	if !ok || entry == nil || len(entry.points) == 0 {
		return []amneziaTrafficSnapshot{}, amneziaTrafficStats{}
	}
	cutoff := time.Now().Unix() - durationSec
	filtered := make([]amneziaTrafficSnapshot, 0, len(entry.points))
	for i := range entry.points {
		if entry.points[i].TS >= cutoff {
			filtered = append(filtered, entry.points[i])
		}
	}
	if len(filtered) == 0 {
		return []amneziaTrafficSnapshot{}, amneziaTrafficStats{}
	}
	out := make([]amneziaTrafficSnapshot, len(filtered))
	copy(out, filtered)
	n := len(out)
	stats := amneziaTrafficStats{Points: int64(n)}
	for i := 1; i < n; i++ {
		dt := out[i].TS - out[i-1].TS
		if dt <= 0 {
			continue
		}
		drx := out[i].Rx - out[i-1].Rx
		dtx := out[i].Tx - out[i-1].Tx
		if drx < 0 || dtx < 0 {
			continue
		}
		rxRate := float64(drx) / float64(dt)
		txRate := float64(dtx) / float64(dt)
		if stats.Points == int64(n) {
			stats.CurrentRx = rxRate
			stats.CurrentTx = txRate
		}
		if rxRate > stats.PeakRate {
			stats.PeakRate = rxRate
		}
		if txRate > stats.PeakRate {
			stats.PeakRate = txRate
		}
		stats.AvgRx += rxRate
		stats.AvgTx += txRate
	}
	if n > 1 {
		stats.AvgRx /= float64(n - 1)
		stats.AvgTx /= float64(n - 1)
	}
	return out, stats
}

func startAmneziaTrafficPoller() {
	if _, err := execWithTimeout(5*time.Second, "sh", "-c", "ls /etc/amnezia/amneziawg/*.conf >/dev/null 2>&1"); err != nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		entries, err := os.ReadDir(amneziaConfDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			name := strings.TrimSuffix(entry.Name(), ".conf")
			running := isAmneziaRunning(name)
			if !running {
				continue
			}
			rxBytes, txBytes := getAmneziaRawBytes(name)
			feedAmneziaTraffic(name, rxBytes, txBytes)
		}
	}
}

func startAmneziaTrafficCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Unix() - 86400
		amneziaTrafficBuf.mu.Lock()
		for name, entry := range amneziaTrafficBuf.entries {
			for len(entry.points) > 0 && entry.points[0].TS < cutoff {
				entry.points = entry.points[1:]
			}
			if len(entry.points) == 0 {
				delete(amneziaTrafficBuf.entries, name)
			}
		}
		amneziaTrafficBuf.mu.Unlock()
	}
}

func (s *Server) getAmneziaStatus(w http.ResponseWriter, r *http.Request) {
	_, err := exec.LookPath("awg")
	installed := err == nil
	version := ""
	if installed {
		out, _ := execWithTimeout(5*time.Second, "awg", "-v")
		v := strings.TrimSpace(string(out))
		if v != "" {
			version = v
			installed = true
		} else {
			installed = false
		}
	}

	status := "idle"
	logBytes, _ := os.ReadFile(filepath.Join(logDir, "amnezia-install.log"))
	logText := string(logBytes)

	stBytes, _ := os.ReadFile(filepath.Join(logDir, "amnezia-install.status"))
	status = strings.TrimSpace(string(stBytes))
	if status == "" && installed {
		status = "completed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"installed":      installed,
		"installStatus":  status,
		"installLogTail": logText,
		"version":        version,
	})
}

func (s *Server) installAmnezia(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	os.WriteFile(filepath.Join(logDir, "amnezia-install.status"), []byte("running"), 0644)
	os.WriteFile(filepath.Join(logDir, "amnezia-install.log"), []byte(""), 0644)
	go func() {
		script := `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "Updating apt..."
apt-get update -q 2>&1 || true
apt-get upgrade -y -q \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" 2>&1 || true

echo "Installing dependencies..."
apt-get install -y -q \
  python3 net-tools curl ufw iptables qrencode bc ca-certificates gnupg \
  build-essential git libmnl-dev pkg-config dkms 2>&1 || true

echo "Installing kernel headers..."
running_kernel="$(uname -r)"
if [[ ! -d "/lib/modules/${running_kernel}/build" ]]; then
  apt-get install -y -q "linux-headers-${running_kernel}" 2>&1 || true
fi
if [[ ! -d "/lib/modules/${running_kernel}/build" ]]; then
  apt-get install -y -q linux-headers-amd64 2>/dev/null || \
  apt-get install -y -q linux-headers-generic 2>/dev/null || true
fi

echo "Building amneziawg kernel module..."
tmp_mod="/tmp/amneziawg-linux-kernel-module"
rm -rf "$tmp_mod"
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$tmp_mod" 2>&1 || {
  echo "Failed to clone kernel module"; exit 1
}
(
  cd "$tmp_mod/src" || exit 1
  make dkms-install 2>&1 || exit 1
  mod_ver=$(grep -oP 'version\s*"\K[^"]+' dkms.conf 2>/dev/null || echo "1.0.0")
  dkms add -m amneziawg -v "$mod_ver" 2>/dev/null || true
  dkms build -m amneziawg -v "$mod_ver" 2>&1 || exit 1
  dkms install -m amneziawg -v "$mod_ver" 2>&1 || exit 1
) || {
  echo "Failed to build kernel module"; exit 1
}
rm -rf "$tmp_mod"

echo "Building amneziawg-tools..."
tmp_tools="/tmp/amneziawg-tools"
rm -rf "$tmp_tools"
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git "$tmp_tools" 2>&1 || {
  echo "Failed to clone tools"; exit 1
}
(
  cd "$tmp_tools/src" || exit 1
  make 2>&1 && make install 2>&1
) || {
  echo "Failed to build tools"; exit 1
}
rm -rf "$tmp_tools"

echo "Loading module..."
modprobe amneziawg 2>/dev/null || true

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 -q 2>&1 || true
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || \
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "Done"
`
		cmd := exec.Command("bash", "-c", script+" 2>&1")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("amnezia install: stdout pipe error: %v", err)
			os.WriteFile(filepath.Join(logDir, "amnezia-install.status"), []byte("failed"), 0644)
			return
		}
		if err := cmd.Start(); err != nil {
			log.Printf("amnezia install: start error: %v", err)
			os.WriteFile(filepath.Join(logDir, "amnezia-install.status"), []byte("failed"), 0644)
			return
		}
		var logBuf bytes.Buffer
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text() + "\n"
			logBuf.WriteString(line)
			os.WriteFile(filepath.Join(logDir, "amnezia-install.log"), []byte(logBuf.String()), 0644)
		}
		if err := cmd.Wait(); err != nil {
			logBuf.WriteString("\n[ERROR] " + err.Error() + "\n")
			os.WriteFile(filepath.Join(logDir, "amnezia-install.log"), []byte(logBuf.String()), 0644)
			os.WriteFile(filepath.Join(logDir, "amnezia-install.status"), []byte("failed"), 0644)
		} else {
			os.WriteFile(filepath.Join(logDir, "amnezia-install.status"), []byte("completed"), 0644)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) importAmneziaConfig(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ConfigText string `json:"configText"`
		Name       string `json:"name"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.ConfigText == "" {
		http.Error(w, "config text required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)

	configText := req.ConfigText
	configText = strings.Replace(configText, "[Interface]", "[Interface]\nTable = off", 1)
	var lines []string
	for _, line := range strings.Split(configText, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "DNS = ") {
			lines = append(lines, line)
		}
	}
	configText = strings.Join(lines, "\n")
	if !strings.Contains(configText, "PersistentKeepalive = ") {
		configText = strings.Replace(configText, "[Peer]", "[Peer]\nPersistentKeepalive = 27", 1)
	}

	os.MkdirAll(amneziaConfDir, 0700)
	confPath := amneziaConfPath(name)
	if err := os.WriteFile(confPath, []byte(configText), 0600); err != nil {
		http.Error(w, "failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	execWithTimeout(5*time.Second, "modprobe", "amneziawg")

	out, upErr := execWithTimeout(30*time.Second, "awg-quick", "up", name)
	if upErr != nil {
		os.Remove(confPath)
		http.Error(w, "awg-quick up failed: "+string(out), http.StatusInternalServerError)
		return
	}

	execWithTimeout(10*time.Second, "systemctl", "enable", "--now", "awg-quick@"+name)

	var publicKey string
	for _, line := range strings.Split(req.ConfigText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PublicKey = ") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey = "))
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"name":      name,
		"publicKey": publicKey,
	})
}

func (s *Server) getAmneziaInterfaces(w http.ResponseWriter, r *http.Request) {
	dir := amneziaConfDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	var result []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		running := isAmneziaRunning(name)
		pubKey := ""
		address := ""
		handshake := ""
		rx := ""
		tx := ""
		rxBytes := int64(0)
		txBytes := int64(0)
		now := time.Now().Unix()
		if running {
			pubKey = getAmneziaPublicKey(name)
			address = getAmneziaAddress(name)
			handshake = getAmneziaHandshake(name)
			rx, tx = getAmneziaTransfer(name)
			rxBytes, txBytes = getAmneziaRawBytes(name)
		}
		result = append(result, map[string]interface{}{
			"name":       name,
			"running":    fmt.Sprintf("%v", running),
			"publicKey":  pubKey,
			"address":    address,
			"endpoint":   getAmneziaEndpoint(name),
			"handshake":  handshake,
			"ping":       getAmneziaPing(name),
			"rx":         rx,
			"tx":         tx,
			"rxBytes":    rxBytes,
			"txBytes":    txBytes,
			"lastUpdate": now,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) getAmneziaInterfaceStats(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	name := parts[0]
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "1h"
	}
	durationSec := int64(3600)
	switch period {
	case "3h":
		durationSec = 3 * 3600
	case "24h":
		durationSec = 24 * 3600
	}
	snaps, stats := getAmneziaTrafficPoints(name, durationSec)
	n := len(snaps)
	if n < 2 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(amneziaTrafficStatsResponse{
			Points: []amneziaTrafficPoint{},
			Stats:  amneziaTrafficStats{},
		})
		return
	}
	points := make([]amneziaTrafficPoint, n)
	points[0] = amneziaTrafficPoint{TS: snaps[0].TS, Rx: 0, Tx: 0}
	for i := 1; i < n; i++ {
		dt := snaps[i].TS - snaps[i-1].TS
		if dt <= 0 {
			points[i] = amneziaTrafficPoint{TS: snaps[i].TS, Rx: 0, Tx: 0}
			continue
		}
		drx := snaps[i].Rx - snaps[i-1].Rx
		dtx := snaps[i].Tx - snaps[i-1].Tx
		var rxRate, txRate float64
		if drx >= 0 {
			rxRate = float64(drx) / float64(dt)
		}
		if dtx >= 0 {
			txRate = float64(dtx) / float64(dt)
		}
		points[i] = amneziaTrafficPoint{TS: snaps[i].TS, Rx: rxRate, Tx: txRate}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(amneziaTrafficStatsResponse{
		Points: points,
		Stats:  stats,
	})
}

func isAmneziaRunning(name string) bool {
	_, err := execWithTimeout(5*time.Second, "awg", "show", name)
	return err == nil
}

func getAmneziaPublicKey(name string) string {
	out, _ := execWithTimeout(5*time.Second, "awg", "show", name)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public key: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "public key: "))
		}
	}
	return ""
}

func getAmneziaHandshake(name string) string {
	out, _ := execWithTimeout(5*time.Second, "awg", "show", name)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "latest handshake: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "latest handshake: "))
		}
	}
	return "никогда"
}

func getAmneziaTransfer(name string) (string, string) {
	out, _ := execWithTimeout(5*time.Second, "awg", "show", name)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "transfer: ") {
			rest := strings.TrimPrefix(line, "transfer: ")
			parts := strings.Split(rest, ", ")
			var rx, tx string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasSuffix(p, "received") {
					rx = strings.TrimSuffix(p, " received")
				} else if strings.HasSuffix(p, "sent") {
					tx = strings.TrimSuffix(p, " sent")
				}
			}
			return rx, tx
		}
	}
	return "0 B", "0 B"
}

func getAmneziaRawBytes(name string) (int64, int64) {
	rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", name)
	txPath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", name)
	rx := int64(0)
	tx := int64(0)
	if data, err := os.ReadFile(rxPath); err == nil {
		rx, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}
	if data, err := os.ReadFile(txPath); err == nil {
		tx, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}
	return rx, tx
}

func getAmneziaAddress(name string) string {
	confPath := amneziaConfPath(name)
	data, err := os.ReadFile(confPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address = ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Address = "))
		}
	}
	return ""
}

func getAmneziaEndpoint(name string) string {
	confPath := amneziaConfPath(name)
	data, err := os.ReadFile(confPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Endpoint = ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Endpoint = "))
		}
	}
	return ""
}

func getAmneziaPing(name string) string {
	out, err := execWithTimeout(5*time.Second, "ping", "-c", "1", "-W", "1", "-I", name, "1.1.1.1")
	if err != nil {
		return "timeout"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "time=") {
			parts := strings.Split(line, "time=")
			if len(parts) > 1 {
				return strings.TrimSpace(strings.Split(parts[1], " ")[0])
			}
		}
	}
	return "timeout"
}

func (s *Server) handleAmneziaInterface(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	if strings.HasSuffix(path, "/stats") {
		s.getAmneziaInterfaceStats(w, r)
		return
	}
	if strings.HasSuffix(path, "/ping") {
		s.checkAmneziaPing(w, r)
		return
	}
	if strings.HasSuffix(path, "/config") {
		if r.Method == http.MethodGet {
			s.getAmneziaInterfaceConfig(w, r)
		} else if r.Method == http.MethodPost {
			s.saveAmneziaInterfaceConfig(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	s.manageAmneziaInterface(w, r)
}

func (s *Server) checkAmneziaPing(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	name := strings.TrimSuffix(path, "/ping")
	if name == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	out, err := execWithTimeout(5*time.Second, "ping", "-c", "1", "-W", "2", "-I", name, "1.1.1.1")
	connected := err == nil
	latency := float64(0)
	text := "timeout"
	if connected {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "time=") {
				parts := strings.Split(line, "time=")
				if len(parts) > 1 {
					text = strings.TrimSpace(strings.Split(parts[1], " ")[0])
					break
				}
			}
		}
		if f, parseErr := strconv.ParseFloat(text, 64); parseErr == nil {
			latency = f
		}
	} else {
		text = "no reply"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connected": connected,
		"latency":   latency,
		"text":      text,
	})
}

func parseAmneziaConfig(content string) amneziaConfigResponse {
	cfg := amneziaConfigResponse{
		MTU:       1420,
		Keepalive: 25,
		JC:        4,
		JMIN:      40,
		JMAX:      70,
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "Address":
			cfg.Address = val
		case "ListenPort":
			// skip
		case "PrivateKey":
			// skip
		case "PublicKey":
			cfg.PublicKey = val
		case "Endpoint":
			cfg.Endpoint = val
		case "AllowedIPs":
			cfg.AllowedIPs = val
		case "DNS":
			cfg.DNS = val
		case "PersistentKeepalive":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.Keepalive = n
			}
		case "MTU":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.MTU = n
			}
		case "JC":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.JC = n
			}
		case "JMIN":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.JMIN = n
			}
		case "JMAX":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.JMAX = n
			}
		case "S1":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.S1 = n
			}
		case "S2":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.S2 = n
			}
		case "S3":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.S3 = n
			}
		case "S4":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.S4 = n
			}
		case "H1":
			cfg.H1 = val
		case "H2":
			cfg.H2 = val
		case "H3":
			cfg.H3 = val
		case "H4":
			cfg.H4 = val
		case "I1":
			cfg.I1 = val
		case "I2":
			cfg.I2 = val
		case "I3":
			cfg.I3 = val
		case "I4":
			cfg.I4 = val
		case "I5":
			cfg.I5 = val
		case "Table":
			cfg.Table = val
		}
	}
	return cfg
}

func writeAmneziaConfig(cfg amneziaConfigResponse) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = <server_key_placeholder>\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", cfg.Address))
	b.WriteString("Table = off\n")
	if cfg.Endpoint == "" {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", 51820))
	}
	if cfg.DNS != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", cfg.DNS))
	}
	b.WriteString(fmt.Sprintf("MTU = %d\n", cfg.MTU))
	b.WriteString(fmt.Sprintf("JC = %d\n", cfg.JC))
	b.WriteString(fmt.Sprintf("JMIN = %d\n", cfg.JMIN))
	b.WriteString(fmt.Sprintf("JMAX = %d\n", cfg.JMAX))
	b.WriteString(fmt.Sprintf("S1 = %d\n", cfg.S1))
	b.WriteString(fmt.Sprintf("S2 = %d\n", cfg.S2))
	b.WriteString(fmt.Sprintf("S3 = %d\n", cfg.S3))
	b.WriteString(fmt.Sprintf("S4 = %d\n", cfg.S4))
	if cfg.H1 != "" {
		b.WriteString(fmt.Sprintf("H1 = %s\n", cfg.H1))
	}
	if cfg.H2 != "" {
		b.WriteString(fmt.Sprintf("H2 = %s\n", cfg.H2))
	}
	if cfg.H3 != "" {
		b.WriteString(fmt.Sprintf("H3 = %s\n", cfg.H3))
	}
	if cfg.H4 != "" {
		b.WriteString(fmt.Sprintf("H4 = %s\n", cfg.H4))
	}
	if cfg.I1 != "" {
		b.WriteString(fmt.Sprintf("I1 = %s\n", cfg.I1))
	}
	if cfg.I2 != "" {
		b.WriteString(fmt.Sprintf("I2 = %s\n", cfg.I2))
	}
	if cfg.I3 != "" {
		b.WriteString(fmt.Sprintf("I3 = %s\n", cfg.I3))
	}
	if cfg.I4 != "" {
		b.WriteString(fmt.Sprintf("I4 = %s\n", cfg.I4))
	}
	if cfg.I5 != "" {
		b.WriteString(fmt.Sprintf("I5 = %s\n", cfg.I5))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", cfg.PublicKey))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", cfg.AllowedIPs))
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", cfg.Endpoint))
	b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", cfg.Keepalive))
	return b.String()
}

func (s *Server) getAmneziaInterfaceConfig(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	name := strings.TrimSuffix(path, "/config")
	if name == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	confPath := amneziaConfPath(name)
	content, err := os.ReadFile(confPath)
	if err != nil {
		http.Error(w, "failed to read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := parseAmneziaConfig(string(content))
	cfg.Name = name
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (s *Server) saveAmneziaInterfaceConfig(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	name := strings.TrimSuffix(path, "/config")
	if name == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}

	var req amneziaConfigResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = name

	confPath := amneziaConfPath(name)
	wasRunning := false
	_, err := execWithTimeout(5*time.Second, "ip", "link", "show", "dev", name)
	wasRunning = err == nil

	if wasRunning {
		execWithTimeout(30*time.Second, "awg-quick", "down", name)
		execWithTimeout(10*time.Second, "systemctl", "disable", "--now", "awg-quick@"+name)
	}

	newConf := writeAmneziaConfig(req)
	privKey := ""
	if existing, err := os.ReadFile(confPath); err == nil {
		lines := strings.Split(string(existing), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PrivateKey = ") {
				privKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey = "))
				break
			}
		}
	}
	if privKey != "" {
		newConf = strings.Replace(newConf, "<server_key_placeholder>", privKey, 1)
	}
	if err := os.WriteFile(confPath, []byte(newConf), 0600); err != nil {
		http.Error(w, "failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if wasRunning {
		if upOut, upErr := execWithTimeout(30*time.Second, "awg-quick", "up", name); upErr != nil {
			http.Error(w, "awg-quick up failed: "+string(upOut), http.StatusInternalServerError)
			return
		}
		execWithTimeout(10*time.Second, "systemctl", "enable", "--now", "awg-quick@"+name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
}

func (s *Server) manageAmneziaInterface(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/amnezia/interface/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "interface name required", http.StatusBadRequest)
		return
	}
	name := parts[0]
	var action string
	if len(parts) >= 2 {
		action = parts[1]
	}

	switch action {
	case "down":
		out, err := execWithTimeout(30*time.Second, "awg-quick", "down", name)
		if err != nil {
			http.Error(w, "awg-quick down failed: "+string(out), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	case "up":
		out, err := execWithTimeout(30*time.Second, "awg-quick", "up", name)
		if err != nil {
			http.Error(w, "awg-quick up failed: "+string(out), http.StatusInternalServerError)
			return
		}
		execWithTimeout(10*time.Second, "systemctl", "enable", "--now", "awg-quick@"+name)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	case "delete":
		execWithTimeout(10*time.Second, "systemctl", "disable", "--now", "awg-quick@"+name)
		execWithTimeout(30*time.Second, "awg-quick", "down", name)
		os.Remove(amneziaConfPath(name))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": name})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}
