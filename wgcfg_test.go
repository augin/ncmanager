package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestGetInterfaceIP(t *testing.T) {
	cases := []struct {
		name   string
		subnet string
		want   string
	}{
		{"default subnet on empty", "", "10.0.0.1"},
		{"typical /24", "10.0.0.0/24", "10.0.0.1"},
		{"other /24", "192.168.5.0/24", "192.168.5.1"},
		{"host address in subnet masked to network", "192.168.5.13/24", "192.168.5.1"},
		{"/16 increments last octet", "172.16.0.0/16", "172.16.0.1"},
		{"invalid subnet", "not-a-cidr", ""},
		{"garbage", "banana", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getInterfaceIP(tc.subnet); got != tc.want {
				t.Errorf("getInterfaceIP(%q) = %q, want %q", tc.subnet, got, tc.want)
			}
		})
	}
}

func TestNextAvailableIP(t *testing.T) {
	t.Run("empty subnet returns server-adjacent ip", func(t *testing.T) {
		got, err := nextAvailableIP(nil, "10.0.0.0/24")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "10.0.0.2/32" {
			t.Errorf("got %q, want 10.0.0.2/32", got)
		}
	})

	t.Run("skips used addresses", func(t *testing.T) {
		peers := []Peer{
			{AllowedIPs: "10.0.0.2/32"},
			{AllowedIPs: "10.0.0.3/32"},
			{AllowedIPs: "10.0.0.5"}, // без суффикса
		}
		got, err := nextAvailableIP(peers, "10.0.0.0/24")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "10.0.0.4/32" {
			t.Errorf("got %q, want 10.0.0.4/32", got)
		}
	})

	t.Run("default subnet on empty string", func(t *testing.T) {
		got, err := nextAvailableIP(nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "10.0.0.2/32" {
			t.Errorf("got %q, want 10.0.0.2/32", got)
		}
	})

	t.Run("full subnet returns error", func(t *testing.T) {
		// /29 => адресов .0...7, usable .1...6 (.0 сеть, .1 сервер)
		peers := []Peer{
			{AllowedIPs: "10.0.0.2/32"},
			{AllowedIPs: "10.0.0.3/32"},
			{AllowedIPs: "10.0.0.4/32"},
			{AllowedIPs: "10.0.0.5/32"},
			{AllowedIPs: "10.0.0.6/32"},
		}
		if _, err := nextAvailableIP(peers, "10.0.0.0/29"); err == nil {
			t.Fatal("expected error for exhausted subnet, got nil")
		}
	})

	t.Run("invalid subnet returns error", func(t *testing.T) {
		if _, err := nextAvailableIP(nil, "wrong"); err == nil {
			t.Fatal("expected error for invalid subnet, got nil")
		}
	})

	t.Run("increments across third octet", func(t *testing.T) {
		peers := []Peer{{AllowedIPs: "10.0.1.255/32"}}
		got, err := nextAvailableIP(peers, "10.0.1.0/24")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "10.0.1.2/32" {
			t.Errorf("got %q, want 10.0.1.2/32", got)
		}
	})
}

func TestToSyncconfConfig(t *testing.T) {
	input := `# комментарий
[Interface]
Address = 10.0.0.1/24
DNS = 1.1.1.1
PrivateKey = PRIVKEY
ListenPort = 51820
PostUp = iptables -A FORWARD -j ACCEPT
PostDown = iptables -D FORWARD -j ACCEPT
MTU = 1280
Table = off
SaveConfig = true
FwMark = 0xca6c

[Peer]
# alice
PublicKey = PUBKEY1
AllowedIPs = 10.0.0.2/32
PresharedKey = PSK
Endpoint = 1.2.3.4:51820
PersistentKeepalive = 25
JUNK = 1
`
	got := toSyncconfConfig(input)

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = PRIVKEY",
		"ListenPort = 51820",
		"FwMark = 0xca6c",
		"[Peer]",
		"PublicKey = PUBKEY1",
		"AllowedIPs = 10.0.0.2/32",
		"PresharedKey = PSK",
		"Endpoint = 1.2.3.4:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output must contain %q\ngot:\n%s", want, got)
		}
	}

	for _, notWant := range []string{
		"Address", "DNS", "PostUp", "PostDown", "MTU", "Table", "SaveConfig",
		"PRIVKEY comment", "#", "JUNK",
	} {
		if notWant == "PRIVKEY comment" {
			continue
		}
		if strings.Contains(got, notWant) {
			t.Errorf("output must not contain %q\ngot:\n%s", notWant, got)
		}
	}
}

func TestAutogenPostUp(t *testing.T) {
	got := autogenPostUp("eth0", 51820)
	want := "iptables -A INPUT -p udp --dport 51820 -j ACCEPT || true; " +
		"iptables -A FORWARD -i eth0 -o %i -j ACCEPT || true; " +
		"iptables -A FORWARD -i %i -j ACCEPT || true; " +
		"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || true; " +
		"ip route add default dev eth0 table 110 || true; " +
		"ip rule add iif %i table 110 || true;"
	if got != want {
		t.Errorf("autogenPostUp mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestAutogenPostUpDefaultIface(t *testing.T) {
	if !strings.Contains(autogenPostUp("", 1), "-i eth0") {
		t.Errorf("empty wanIface must default to eth0: %s", autogenPostUp("", 1))
	}
}

func TestAutogenPostDown(t *testing.T) {
	got := autogenPostDown("wan0", 9999)
	for _, want := range []string{
		"iptables -D INPUT -p udp --dport 9999",
		"-i wan0 -o %i",
		"-o wan0 -j MASQUERADE",
		"ip route del default dev wan0 table 110",
		"ip rule del iif %i table 110",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("autogenPostDown must contain %q\ngot: %s", want, got)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"PublicKey = abc123", "abc123"},
		{"PublicKey=abc123", "abc123"},
		{"  PublicKey = spaced  ", ""},
		{"PrivateKey = abc", ""},
		{"PublicKey = ", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := parsePublicKey(tc.in); got != tc.want {
			t.Errorf("parsePublicKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsBase64(t *testing.T) {
	validKey := strings.Repeat("A", 43) + "="
	cases := []struct {
		in   string
		want bool
	}{
		{validKey, true},
		{strings.Repeat("A", 44), true},
		{strings.Repeat("A", 30) + "/def+ghi=", true},
		{"", false},
		{"short", false},
		{strings.Repeat("A", 31), false},
		{strings.Repeat("A", 43) + "-", false},
		{strings.Repeat("A", 43) + "!", false},
	}
	for _, tc := range cases {
		if got := isBase64(tc.in); got != tc.want {
			t.Errorf("isBase64(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestGeneratePeerConfig(t *testing.T) {
	peer := &Peer{
		Name:       "alice",
		PrivateKey: "PRIVKEY",
		PublicKey:  "PUBKEY",
		AllowedIPs: "10.0.0.2/32",
	}
	got := generatePeerConfig(peer, "SRVPUB", "wg0", "1.2.3.4", 51820, "1.1.1.1")

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = PRIVKEY",
		"Address = 10.0.0.2/32",
		"DNS = 1.1.1.1",
		"[Peer]",
		"PublicKey = SRVPUB",
		"Endpoint = 1.2.3.4:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("peer config must contain %q\ngot:\n%s", want, got)
		}
	}
}

func TestGeneratePeerConfigWithoutDNS(t *testing.T) {
	peer := &Peer{PrivateKey: "PRIVKEY", AllowedIPs: "10.0.0.2/32"}
	got := generatePeerConfig(peer, "SRVPUB", "wg0", "1.2.3.4", 51820, "")
	if strings.Contains(got, "DNS") {
		t.Errorf("empty dns must not produce DNS line:\n%s", got)
	}
}

func TestGenerateKeeneticServerConfig(t *testing.T) {
	peer := &Peer{Name: "alice", PublicKey: "PUBKEY", AllowedIPs: "10.0.0.2/32"}
	got := generateKeeneticServerConfig(peer, "SRVPUB", "wg1", "5.6.7.8", 51820, "10.9.0.0/24", "")

	for _, want := range []string{
		"[Interface]",
		"Address = 10.9.0.1/24",
		"ListenPort = 51820",
		"PrivateKey = SRVPUB",
		"--dport 51820",
		"-i eth0", // wanIface по умолчанию
		"[Peer]",
		"# alice",
		"PublicKey = PUBKEY",
		"AllowedIPs = 10.0.0.2/32",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("keenetic server config must contain %q\ngot:\n%s", want, got)
		}
	}
}

func TestGenerateKeeneticServerConfigFallbackSubnet(t *testing.T) {
	peer := &Peer{Name: "a", PublicKey: "P"}
	got := generateKeeneticServerConfig(peer, "K", "wg1", "1.1.1.1", 1, "bogus", "wan0")
	if !strings.Contains(got, "Address = 10.0.0.1/24") {
		t.Errorf("invalid subnet must fall back to 10.0.0.1/24:\n%s", got)
	}
	if !strings.Contains(got, "-i wan0") {
		t.Errorf("explicit wan iface missing:\n%s", got)
	}
}

func TestGetCIDRPrefix(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := getCIDRPrefix(ipnet); got != 24 {
		t.Errorf("getCIDRPrefix = %d, want 24", got)
	}
}

// fakeKey — валидная по isBase64 строка длиной 44 символа.
const fakeKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestParseWgDumpEmpty(t *testing.T) {
	if _, err := parseWgDump("", "pub"); err == nil {
		t.Error("пустой вывод dump должен давать ошибку")
	}
}

func TestParseWgDumpClassicFormat(t *testing.T) {
	raw := fakeKey + "\t" + fakeKey + "\t51820\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t123\t456\n" +
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\n"
	info, err := parseWgDump(raw, "SERVERPUB")
	if err != nil {
		t.Fatal(err)
	}
	if info.PublicKey != "SERVERPUB" {
		t.Errorf("PublicKey = %q", info.PublicKey)
	}
	if info.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", info.ListenPort)
	}
	if len(info.Peers) != 2 {
		t.Fatalf("Peers = %d, want 2", len(info.Peers))
	}
	p := info.Peers[0]
	if p.Endpoint != "1.2.3.4:51820" || p.AllowedIPs != "10.0.0.2/32" {
		t.Errorf("peer 0: endpoint=%q allowed=%q", p.Endpoint, p.AllowedIPs)
	}
	if p.TransferRx != 123 || p.TransferTx != 456 {
		t.Errorf("peer 0: rx=%d tx=%d", p.TransferRx, p.TransferTx)
	}
	if want := time.Unix(1700000000, 0); !p.LastHandshake.Equal(want) {
		t.Errorf("peer 0: handshake=%v, want %v", p.LastHandshake, want)
	}
	// Handshake "0" не даёт времени.
	if !info.Peers[1].LastHandshake.IsZero() {
		t.Errorf("peer 1: handshake = %v, want zero", info.Peers[1].LastHandshake)
	}
}

func TestParseWgDumpPeerKeywordFormat(t *testing.T) {
	raw := "peer BBBB\t2026-01-02\t15:04:05\t10\t20\t10.0.0.5/32\t5.6.7.8:1234\n"
	info, err := parseWgDump(raw, "SERVERPUB")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1", len(info.Peers))
	}
	p := info.Peers[0]
	if p.PublicKey != "BBBB" || p.AllowedIPs != "10.0.0.5/32" || p.Endpoint != "5.6.7.8:1234" {
		t.Errorf("peer: %+v", p)
	}
	if p.TransferRx != 10 || p.TransferTx != 20 {
		t.Errorf("rx=%d tx=%d", p.TransferRx, p.TransferTx)
	}
	if p.LastHandshake.Year() != 2026 {
		t.Errorf("handshake = %v", p.LastHandshake)
	}
}

func TestParseWgDumpSkipsGarbage(t *testing.T) {
	raw := "\n\ngarbage line\n   \n" + fakeKey + "\t" + fakeKey + "\t1234\n"
	info, err := parseWgDump(raw, "SERVERPUB")
	if err != nil {
		t.Fatal(err)
	}
	if info.ListenPort != 1234 {
		t.Errorf("ListenPort = %d, want 1234", info.ListenPort)
	}
	if len(info.Peers) != 0 {
		t.Errorf("Peers = %d, want 0", len(info.Peers))
	}
}

func TestRenderWgConfigBasic(t *testing.T) {
	cfg := &Config{Subnet: "10.9.0.0/24", WGPort: 51820, PostUp: "up-cmd", PostDown: "down-cmd"}
	peers := []Peer{{Name: "alice", PublicKey: "APUB", AllowedIPs: "10.9.0.2/32"}}
	got, serverAddr, err := renderWgConfig(cfg, peers, "SPRIV")
	if err != nil {
		t.Fatal(err)
	}
	if serverAddr != "10.9.0.1/24" {
		t.Errorf("serverAddr = %q, want 10.9.0.1/24", serverAddr)
	}
	for _, want := range []string{
		"[Interface]\n",
		"Address = 10.9.0.1/24\n",
		"ListenPort = 51820\n",
		"PrivateKey = SPRIV\n",
		"PostUp = up-cmd\n",
		"PostDown = down-cmd\n",
		"\n[Peer]\n",
		"# alice\n",
		"PublicKey = APUB\n",
		"AllowedIPs = 10.9.0.2/32\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("конфиг не содержит %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "iptables") {
		t.Error("при заданных PostUp/PostDown не должно подставляться iptables-значение по умолчанию")
	}
}

func TestRenderWgConfigDefaults(t *testing.T) {
	cfg := &Config{WGPort: 1}
	got, serverAddr, err := renderWgConfig(cfg, nil, "SPRIV")
	if err != nil {
		t.Fatal(err)
	}
	if serverAddr != "10.0.0.1/24" {
		t.Errorf("serverAddr = %q, want 10.0.0.1/24 (подсеть по умолчанию)", serverAddr)
	}
	if !strings.Contains(got, "iptables -A INPUT") || !strings.Contains(got, "-i eth0") {
		t.Errorf("нет PostUp по умолчанию с eth0:\n%s", got)
	}
	if !strings.Contains(got, "iptables -D INPUT") {
		t.Errorf("нет PostDown по умолчанию:\n%s", got)
	}
}

func TestRenderWgConfigInvalidSubnet(t *testing.T) {
	if _, _, err := renderWgConfig(&Config{Subnet: "bogus"}, nil, "k"); err == nil {
		t.Error("некорректная подсеть должна давать ошибку")
	}
}
