package main

import "testing"

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"latin passthrough", "alice", "alice"},
		{"latin with digits and dashes", "peer-01_x", "peer-01_x"},
		{"cyrillic translit", "Тестовый", "testovyy"},
		{"mixed cyrillic latin digits", "Пир №5!", "pir_5"},
		{"special chars collapsed", "!!!", "peer"},
		{"empty string", "", "peer"},
		{"underscores trimmed", "__abc__", "abc"},
		{"spaces become underscore", "my peer", "my_peer"},
		{"uppercase latin preserved", "Alice", "Alice"},
		{"full sentence", "Домашний интернет (МТС)", "domashniy_internet_mts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeFilename(tc.in); got != tc.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeGroupSlug(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"latin lowercased", "Advertising", "advertising"},
		{"cyrillic translit", "Разные Имена!", "raznye_imena"},
		{"digits kept", "ru 2024", "ru_2024"},
		{"dash becomes underscore", "ru-2024", "ru_2024"},
		{"empty", "", ""},
		{"hard sign dropped", "съёмка", "syomka"},
		{"long names truncated to 20", "очень длинное название группы", "ochen_dlinnoe_nazvan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeGroupSlug(tc.in); got != tc.want {
				t.Errorf("sanitizeGroupSlug(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeGroupSlugLengthLimit(t *testing.T) {
	got := sanitizeGroupSlug("a-very-long-group-name-that-never-fits")
	if len(got) > 20 {
		t.Errorf("slug longer than 20 chars: %q (len %d)", got, len(got))
	}
}

func TestDnsGroupRe(t *testing.T) {
	matching := []string{"route_NCM1", "abc_NCM12", "x_NCM999"}
	for _, g := range matching {
		if !dnsGroupRe.MatchString(g) {
			t.Errorf("%q must match dnsGroupRe", g)
		}
	}
	notMatching := []string{"Wireguard1", "mygroup", "_NCM1", "route_NCM", "FastEthernet0/Vlan1"}
	for _, g := range notMatching {
		if dnsGroupRe.MatchString(g) {
			t.Errorf("%q must NOT match dnsGroupRe", g)
		}
	}
}
