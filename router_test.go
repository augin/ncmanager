package main

import "testing"

func TestRouterBaseURLs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		// IP — сначала http, затем https
		{"192.168.1.1", []string{"http://192.168.1.1", "https://192.168.1.1"}},
		{"10.0.0.1:8080", []string{"http://10.0.0.1:8080", "https://10.0.0.1:8080"}},
		// Домен — сначала https, затем http
		{"keenetik0.netcraze.pro", []string{"https://keenetik0.netcraze.pro", "http://keenetik0.netcraze.pro"}},
		{"router.local:8443", []string{"https://router.local:8443", "http://router.local:8443"}},
		// IPv6 оборачивается в скобки
		{"::1", []string{"http://[::1]", "https://[::1]"}},
		{"[::1]:8080", []string{"http://[::1]:8080", "https://[::1]:8080"}},
		// Явная схема используется как есть
		{"https://router.local", []string{"https://router.local"}},
		{"http://10.0.0.1/", []string{"http://10.0.0.1"}},
	}
	for _, tc := range cases {
		got := routerBaseURLs(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("routerBaseURLs(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("routerBaseURLs(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

func TestRouterBaseURLsRemembersWorkingScheme(t *testing.T) {
	const host = "10.99.99.99"
	if got := routerBaseURLs(host); got[0] != "http://"+host {
		t.Fatalf("before remember: got %v, want http first", got)
	}
	rememberRouterScheme(host, "https")
	got := routerBaseURLs(host)
	if got[0] != "https://"+host || got[1] != "http://"+host {
		t.Errorf("after remember: got %v, want https first", got)
	}
}

func TestParseCIDRToMask(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantMask string
	}{
		{"10.0.0.5/24", "10.0.0.5", "255.255.255.0"},
		{"192.168.1.1/16", "192.168.1.1", "255.255.0.0"},
		{"10.0.0.2/32", "10.0.0.2", "255.255.255.255"},
		{"172.16.0.1/8", "172.16.0.1", "255.0.0.0"},
		{"bad", "", ""},
		{"", "", ""},
		{"10.0.0.0/24junk", "", ""},
	}
	for _, tc := range cases {
		ip, mask := parseCIDRToMask(tc.in)
		if ip != tc.wantIP || mask != tc.wantMask {
			t.Errorf("parseCIDRToMask(%q) = (%q, %q), want (%q, %q)", tc.in, ip, mask, tc.wantIP, tc.wantMask)
		}
	}

	if ip, mask := parseCIDRToMask("2001:db8::1/64"); ip != "" || mask != "" {
		t.Errorf("IPv6 must be rejected, got (%q, %q)", ip, mask)
	}
}

func TestParseComponentInfoDescription(t *testing.T) {
	info := parseComponentInfo("wireguard", map[string]any{
		"description": map[string]any{"EN": "WireGuard", "RU": "ВайрГард"},
	})
	if info.Description != "WireGuard" {
		t.Errorf("Description = %q, want WireGuard", info.Description)
	}
	if info.Name != "wireguard" {
		t.Errorf("Name = %q", info.Name)
	}

	// без EN — берём первое непустое значение
	info = parseComponentInfo("x", map[string]any{
		"description": map[string]any{"RU": "Текст"},
	})
	if info.Description != "Текст" {
		t.Errorf("fallback Description = %q", info.Description)
	}

	// описание строкой
	info = parseComponentInfo("x", map[string]any{"description": "Plain"})
	if info.Description != "Plain" {
		t.Errorf("string Description = %q", info.Description)
	}
}

func TestParseComponentInfoInstalled(t *testing.T) {
	cases := []struct {
		value any
		want  bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"false", false},
		{"yes", true},
		{"no", false},
		{"on", true},
		{"off", false},
		{"1", true},
		{"0", false},
		{"1.2.3", true},   // версия — содержит цифры
		{"unknown", true}, // прочие значения считаются установленными
	}
	for _, tc := range cases {
		info := parseComponentInfo("c", map[string]any{"installed": tc.value})
		if info.Installed != tc.want {
			t.Errorf("installed=%v: Installed=%v, want %v", tc.value, info.Installed, tc.want)
		}
	}
}

func TestParseComponentInfoSize(t *testing.T) {
	info := parseComponentInfo("c", map[string]any{"size": float64(1024)})
	if info.Size != 1024 {
		t.Errorf("float size = %d, want 1024", info.Size)
	}
	info = parseComponentInfo("c", map[string]any{"size": "2048"})
	if info.Size != 2048 {
		t.Errorf("string size = %d, want 2048", info.Size)
	}
	info = parseComponentInfo("c", map[string]any{"size": "abc"})
	if info.Size != 0 {
		t.Errorf("garbage size = %d, want 0", info.Size)
	}
}

func TestFindComponent(t *testing.T) {
	comps := map[string]ComponentInfo{
		"wireguard": {Name: "wireguard", Installed: true},
		"dns-tls":   {Name: "dns-tls"},
	}

	if info, ok := findComponent(comps, "wireguard"); !ok || !info.Installed {
		t.Errorf("exact match failed: %+v %v", info, ok)
	}
	if info, ok := findComponent(comps, "DNS-TLS"); !ok || info.Name != "dns-tls" {
		t.Errorf("case-insensitive match failed: %+v %v", info, ok)
	}
	if _, ok := findComponent(comps, "missing"); ok {
		t.Error("missing component must not be found")
	}
}

func TestIsSystemComponent(t *testing.T) {
	for _, name := range []string{"firmware", "local", "component", "group", "sandbox", "changelog", "base"} {
		if !isSystemComponent(name) {
			t.Errorf("%q must be a system component", name)
		}
	}
	for _, name := range []string{"wireguard", "dns-tls", "user"} {
		if isSystemComponent(name) {
			t.Errorf("%q must NOT be a system component", name)
		}
	}
}
