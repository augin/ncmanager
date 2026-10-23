package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func generateKeyPair() (priv, pub string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", "genkey")
	privBuf := new(bytes.Buffer)
	cmd.Stdout = privBuf
	if err = cmd.Run(); err != nil {
		return "", "", fmt.Errorf("wg genkey failed: %w", err)
	}
	priv = strings.TrimSpace(privBuf.String())

	cmd2 := exec.CommandContext(ctx, "wg", "pubkey")
	cmd2.Stdin = strings.NewReader(priv)
	pubBuf := new(bytes.Buffer)
	cmd2.Stdout = pubBuf
	if err = cmd2.Run(); err != nil {
		return "", "", fmt.Errorf("wg pubkey failed: %w", err)
	}
	pub = strings.TrimSpace(pubBuf.String())
	return
}

func getInterfaceIP(subnet string) string {
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	base := ipnet.IP
	serverIP := make(net.IP, len(base))
	copy(serverIP, base)
	serverIP[3]++
	return serverIP.String()
}

func nextAvailableIP(peers []Peer, subnet string) (string, error) {
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	base := ipnet.IP
	maskSize, _ := ipnet.Mask.Size()

	used := make(map[string]bool)
	networkAddr := base.String()
	used[networkAddr] = true
	serverIP := make(net.IP, len(base))
	copy(serverIP, base)
	serverIP[3]++
	used[serverIP.String()] = true

	for _, p := range peers {
		parts := strings.Split(p.AllowedIPs, "/")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			used[ip] = true
		}
	}

	for i := 1; i < (1<<(32-maskSize))-1; i++ {
		ip := make(net.IP, len(base))
		copy(ip, base)
		v := i
		for j := 3; j >= 0; j-- {
			if v > 0 {
				octet := int(base[j]) + (v & 0xFF)
				ip[j] = byte(octet)
				v >>= 8
			}
		}
		candidate := ip.String()
		if !used[candidate] {
			return candidate + "/32", nil
		}
	}
	return "", fmt.Errorf("no available IP in subnet %s", subnet)
}

func checkWireGuardStatus(iface string) (bool, *wgInfo, error) {
	out, err := execWithTimeout(5*time.Second, "wg", "show", iface, "public-key")
	if err != nil {
		return false, nil, err
	}
	pubKey := strings.TrimSpace(string(out))

	out, err = execWithTimeout(5*time.Second, "wg", "show", iface, "dump")
	if err != nil {
		return false, nil, err
	}
	info, err := parseWgDump(strings.TrimSpace(string(out)), pubKey)
	if err != nil {
		return false, nil, err
	}
	return true, info, nil
}

// parseWgDump разбирает вывод `wg show <iface> dump` (чистая функция,
// выделена для тестируемости).

// parseWgDump разбирает вывод `wg show <iface> dump` (чистая функция,
// выделена для тестируемости).
func parseWgDump(raw string, pubKey string) (*wgInfo, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty output")
	}
	lines := strings.Split(raw, "\n")
	info := &wgInfo{PublicKey: pubKey}
	interfaceParsed := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if !interfaceParsed && isBase64(parts[0]) && len(parts) >= 3 {
			// interface header: privkey pubkey port
			if len(parts) > 2 {
				fmt.Sscanf(parts[2], "%d", &info.ListenPort)
			}
			interfaceParsed = true
			continue
		}
		if isBase64(parts[0]) && len(parts) >= 7 {
			// Peer line: pubkey	preshared	endpoint	allowedips	handshake_ts	rx	tx...
			p := wgPeer{PublicKey: parts[0]}
			if len(parts) > 2 {
				p.Endpoint = parts[2]
			}
			if len(parts) > 3 {
				p.AllowedIPs = parts[3]
			}
			if len(parts) > 4 && parts[4] != "0" && parts[4] != "(none)" {
				ts, _ := strconv.ParseInt(parts[4], 10, 64)
				if ts > 0 {
					p.LastHandshake = time.Unix(ts, 0)
				}
			}
			if len(parts) > 5 {
				fmt.Sscanf(parts[5], "%d", &p.TransferRx)
			}
			if len(parts) > 6 {
				fmt.Sscanf(parts[6], "%d", &p.TransferTx)
			}
			info.Peers = append(info.Peers, p)
		} else if parts[0] == "peer" {
			// Newer format with "peer" keyword
			p := wgPeer{PublicKey: parts[1]}
			if len(parts) > 3 {
				p.LastHandshake, _ = time.Parse("2006-01-02 15:04:05", parts[2]+" "+parts[3])
			}
			if len(parts) > 4 {
				fmt.Sscanf(parts[4], "%d", &p.TransferRx)
			}
			if len(parts) > 5 {
				fmt.Sscanf(parts[5], "%d", &p.TransferTx)
			}
			if len(parts) > 6 {
				p.AllowedIPs = parts[6]
			}
			if len(parts) > 7 {
				p.Endpoint = parts[7]
			}
			info.Peers = append(info.Peers, p)
		}
	}
	return info, nil
}

func syncPeersWithWireGuard(cfg *Config, peers []Peer) error {
	if cfg == nil {
		return nil
	}
	_, info, err := checkWireGuardStatus("wg0")
	if err != nil {
		return err
	}
	peerMap := make(map[string]wgPeer)
	for _, p := range info.Peers {
		peerMap[p.PublicKey] = p
	}
	for i := range peers {
		if p, ok := peerMap[peers[i].PublicKey]; ok {
			peers[i].LastHandshake = p.LastHandshake
			peers[i].TransferRx = p.TransferRx
			peers[i].TransferTx = p.TransferTx
			peers[i].Endpoint = p.Endpoint
		}
	}
	return nil
}

func parsePublicKey(line string) string {
	for _, prefix := range []string{"PublicKey = ", "PublicKey="} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func syncconfRemovePeer(publicKey string) error {
	out, err := execWithTimeout(5*time.Second, "wg", "showconf", "wg0")
	if err != nil {
		return fmt.Errorf("wg showconf failed: %w, output: %s", err, string(out))
	}

	var buf strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(out))
	inPeer := false
	skipPeer := false
	var peerLines []string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[Peer]") {
			if inPeer && !skipPeer {
				buf.WriteString(strings.Join(peerLines, "\n") + "\n")
			}
			inPeer = true
			skipPeer = false
			peerLines = []string{line}
			continue
		}

		if inPeer {
			peerLines = append(peerLines, line)
			if pk := parsePublicKey(trimmed); pk != "" {
				skipPeer = (pk == publicKey)
			}
			continue
		}

		buf.WriteString(line + "\n")
	}

	if inPeer && !skipPeer {
		buf.WriteString(strings.Join(peerLines, "\n") + "\n")
	}

	tmpName, err := wgSyncTempFile(buf.String())
	if err != nil {
		return err
	}
	defer os.Remove(tmpName)

	if out, err := execWithTimeout(10*time.Second, "wg", "syncconf", "wg0", tmpName); err != nil {
		return fmt.Errorf("wg syncconf failed: %v, output: %s", err, string(out))
	}
	return nil
}

func syncconfAddPeer(peer Peer) error {
	out, err := execWithTimeout(5*time.Second, "wg", "showconf", "wg0")
	if err != nil {
		return fmt.Errorf("wg showconf failed: %w, output: %s", err, string(out))
	}

	peerBlock := fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s\n", peer.Name, peer.PublicKey, peer.AllowedIPs)

	tmpName, err := wgSyncTempFile(string(out) + peerBlock)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName)

	if out, err := execWithTimeout(10*time.Second, "wg", "syncconf", "wg0", tmpName); err != nil {
		return fmt.Errorf("wg syncconf failed: %v, output: %s", err, string(out))
	}
	return nil
}

func wgSyncTempFile(content string) (string, error) {
	dir := filepath.Dir(wgConfigFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, "wg0.syncconf-*.conf")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// toSyncconfConfig strips wg-quick-only directives (Address, DNS, PostUp, PostDown,
// MTU, Table, SaveConfig) so a wg-quick-style config can be fed to `wg syncconf`,
// which only understands wireguard-native settings.

// toSyncconfConfig strips wg-quick-only directives (Address, DNS, PostUp, PostDown,
// MTU, Table, SaveConfig) so a wg-quick-style config can be fed to `wg syncconf`,
// which only understands wireguard-native settings.
func toSyncconfConfig(cfg string) string {
	keepIface := map[string]bool{"PrivateKey": true, "ListenPort": true, "FwMark": true}
	keepPeer := map[string]bool{"PublicKey": true, "PresharedKey": true, "AllowedIPs": true, "Endpoint": true, "PersistentKeepalive": true}
	var b strings.Builder
	section := ""
	sc := bufio.NewScanner(strings.NewReader(cfg))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "[Interface]":
			section = "iface"
			b.WriteString(line + "\n")
			continue
		case "[Peer]":
			section = "peer"
			b.WriteString(line + "\n")
			continue
		}
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
		if (section == "iface" && keepIface[key]) || (section == "peer" && keepPeer[key]) {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func autogenPostUp(wanIface string, wgPort int) string {
	if wanIface == "" {
		wanIface = "eth0"
	}
	return fmt.Sprintf("iptables -A INPUT -p udp --dport %d -j ACCEPT || true; iptables -A FORWARD -i %s -o %%i -j ACCEPT || true; iptables -A FORWARD -i %%i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE || true; ip route add default dev %s table 110 || true; ip rule add iif %%i table 110 || true;", wgPort, wanIface, wanIface, wanIface)
}

func autogenPostDown(wanIface string, wgPort int) string {
	if wanIface == "" {
		wanIface = "eth0"
	}
	return fmt.Sprintf("iptables -D INPUT -p udp --dport %d -j ACCEPT || true; iptables -D FORWARD -i %s -o %%i -j ACCEPT || true; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE || true; ip route del default dev %s table 110 || true; ip rule del iif %%i table 110 || true;", wgPort, wanIface, wanIface, wanIface)
}

func generateWgConfig(cfg *Config, peers []Peer) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	serverPrivBytes, err := loadPrivateKey(serverPrivateKeyFile)
	if err != nil || len(serverPrivBytes) == 0 {
		priv, _, genErr := generateKeyPair()
		if genErr != nil {
			return fmt.Errorf("failed to generate server key: %w", genErr)
		}
		if err := savePrivateKey(serverPrivateKeyFile, priv); err != nil {
			return fmt.Errorf("failed to save server key: %w", err)
		}
		serverPrivBytes = []byte(priv)
	}
	serverPriv := strings.TrimSpace(string(serverPrivBytes))

	content, serverAddr, err := renderWgConfig(cfg, peers, serverPriv)
	if err != nil {
		return err
	}
	log.Printf("generateWgConfig: subnet=%s serverAddr=%s peers=%d", cfg.Subnet, serverAddr, len(peers))
	return writeFileAtomic(wgConfigFile, []byte(content))
}

// renderWgConfig собирает текст конфигурации интерфейса WireGuard
// (чистая функция, выделена для тестируемости). Возвращает конфиг и
// адрес сервера в подсети.

// renderWgConfig собирает текст конфигурации интерфейса WireGuard
// (чистая функция, выделена для тестируемости). Возвращает конфиг и
// адрес сервера в подсети.
func renderWgConfig(cfg *Config, peers []Peer, serverPriv string) (string, string, error) {
	subnet := cfg.Subnet
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	serverIP := ipnet.IP
	serverIP = net.IP{serverIP[0], serverIP[1], serverIP[2], serverIP[3] + 1}
	serverAddr := fmt.Sprintf("%s/%d", serverIP.String(), getCIDRPrefix(ipnet))

	wanIface := cfg.WanInterface
	if wanIface == "" {
		wanIface = "eth0"
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.WGPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPriv))
	if cfg.PostUp != "" {
		b.WriteString(fmt.Sprintf("PostUp = %s\n", cfg.PostUp))
	} else {
		b.WriteString(fmt.Sprintf("PostUp = iptables -A INPUT -p udp --dport %d -j ACCEPT || true; iptables -A FORWARD -i %s -o %%i -j ACCEPT || true; iptables -A FORWARD -i %%i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE || true; ip route add default dev %s table 110 || true; ip rule add iif %%i table 110 || true;\n", cfg.WGPort, wanIface, wanIface, wanIface))
	}
	if cfg.PostDown != "" {
		b.WriteString(fmt.Sprintf("PostDown = %s\n", cfg.PostDown))
	} else {
		b.WriteString(fmt.Sprintf("PostDown = iptables -D INPUT -p udp --dport %d -j ACCEPT || true; iptables -D FORWARD -i %s -o %%i -j ACCEPT || true; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE || true; ip route del default dev %s table 110 || true; ip rule del iif %%i table 110 || true;\n", cfg.WGPort, wanIface, wanIface, wanIface))
	}
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("# %s\n", p.Name))
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey))
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", p.AllowedIPs))
	}
	return b.String(), serverAddr, nil
}

func generatePeerConfig(peer *Peer, serverPub, iface, endpoint string, wgPort int, dns string) string {
	peerPriv := peer.PrivateKey
	if peerPriv == "" {
		peerPriv, _, _ = generateKeyPair()
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", peerPriv))
	b.WriteString(fmt.Sprintf("Address = %s\n", peer.AllowedIPs))
	if dns != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", dns))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", strings.TrimSpace(string(serverPub))))
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", endpoint, wgPort))
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

func savePrivateKey(path, key string) error {
	return os.WriteFile(path, []byte(key), 0600)
}

func loadPrivateKey(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func getPublicKeyFromPrivate(privKeyBytes []byte) (string, error) {
	trimmed := strings.TrimSpace(string(privKeyBytes))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = bytes.NewReader([]byte(trimmed))
	pubBuf := new(bytes.Buffer)
	cmd.Stdout = pubBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg pubkey failed: %w", err)
	}
	return strings.TrimSpace(pubBuf.String()), nil
}
