package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestPlanRouteGroups(t *testing.T) {
	// разбиение по 300 элементов, имена _NCM1.._NCM3
	route := routeApply{Name: "Мой маршрут", Domains: make([]string, 650)}
	for i := range route.Domains {
		route.Domains[i] = fmt.Sprintf("d%d.example", i)
	}
	route.Subnets = []string{"10.0.0.0/24"}
	groups := planRouteGroups(route)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	if groups[0].Name != "moy_marshrut_NCM1" || groups[1].Name != "moy_marshrut_NCM2" || groups[2].Name != "moy_marshrut_NCM3" {
		t.Errorf("unexpected names: %s %s %s", groups[0].Name, groups[1].Name, groups[2].Name)
	}
	if len(groups[0].Items) != 300 || len(groups[1].Items) != 300 || len(groups[2].Items) != 51 {
		t.Errorf("unexpected chunk sizes: %d %d %d", len(groups[0].Items), len(groups[1].Items), len(groups[2].Items))
	}
	last := groups[2].Items[len(groups[2].Items)-1]
	if last != "10.0.0.0/24" {
		t.Errorf("subnets must go after domains, got last item %q", last)
	}

	// пустой маршрут не даёт групп
	if planRouteGroups(routeApply{Name: "x"}) != nil {
		t.Error("empty route must produce no groups")
	}

	// slug из не-латиницы -> fallback
	g := planRouteGroups(routeApply{Name: "!!!", Domains: []string{"a"}})
	if len(g) != 1 || g[0].Name != "route_NCM1" {
		t.Errorf("slug fallback failed: %+v", g)
	}
}

func TestVerifyDnsRoutesState(t *testing.T) {
	routes := []routeApply{
		{Name: "Включён", Domains: []string{"a.com", "b.com"}, Enabled: true},
		{Name: "Выключен", Domains: []string{"c.com"}, Enabled: false},
	}
	groups, dnsRoutes := map[string][]string{}, map[string]map[string]bool{}

	// всё на месте -> без проблем
	groups["vklyuchyon_NCM1"] = []string{"a.com", "b.com"}
	groups["vyklyuchen_NCM1"] = []string{"c.com"}
	dnsRoutes["vklyuchyon_NCM1"] = map[string]bool{"Wireguard1": true}
	if p := verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes); len(p) != 0 {
		t.Errorf("expected no problems, got %v", p)
	}

	// группа не найдена
	delete(groups, "vyklyuchen_NCM1")
	p := verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes)
	if len(p) != 1 || !strings.Contains(p[0], "не найдена") {
		t.Errorf("expected missing group problem, got %v", p)
	}

	// не хватает элементов
	groups["vyklyuchen_NCM1"] = []string{"c.com", "d.com", "e.com"}
	groups["vklyuchyon_NCM1"] = []string{"a.com"} // b.com отсутствует
	p = verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes)
	found := false
	for _, s := range p {
		if strings.Contains(s, "отсутствует 1 из 2") && strings.Contains(s, "b.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing items problem, got %v", p)
	}

	// у включённого маршрута нет dns-proxy маршрута
	delete(dnsRoutes, "vklyuchyon_NCM1")
	p = verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes)
	found = false
	for _, s := range p {
		if strings.Contains(s, "dns-proxy маршрут vklyuchyon_NCM1 → Wireguard1 не найден") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing dns-proxy route problem, got %v", p)
	}

	// dns-proxy маршрут ведёт не на тот интерфейс
	dnsRoutes["vklyuchyon_NCM1"] = map[string]bool{"Wireguard0": true}
	p = verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes)
	found = false
	for _, s := range p {
		if strings.Contains(s, "ведёт на Wireguard0 вместо Wireguard1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected wrong interface problem, got %v", p)
	}

	// отключённый маршрут, у которого остался dns-proxy маршрут
	dnsRoutes["vyklyuchen_NCM1"] = map[string]bool{"Wireguard1": true}
	p = verifyDnsRoutesState("Wireguard1", routes, groups, dnsRoutes)
	found = false
	for _, s := range p {
		if strings.Contains(s, "отключён, но dns-proxy маршрут") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected stale route problem for disabled route, got %v", p)
	}
}

func TestParseFqdnGroups(t *testing.T) {
	dump := map[string]any{
		"object-group": map[string]any{
			"fqdn": map[string]any{
				"grp1": map[string]any{
					"include": []any{
						map[string]any{"address": "a.com"},
						map[string]any{"address": "b.com"},
					},
				},
				"grp2": map[string]any{
					"include": map[string]any{"address": "c.com"},
				},
				"grp3": map[string]any{
					"include": []any{"d.com", "e.com"},
				},
				"grp4": "garbage",
			},
		},
	}
	got := parseFqdnGroups(dump["object-group"])
	want := map[string][]string{
		"grp1": {"a.com", "b.com"},
		"grp2": {"c.com"},
		"grp3": {"d.com", "e.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, items := range want {
		if strings.Join(got[name], ",") != strings.Join(items, ",") {
			t.Errorf("group %s: got %v, want %v", name, got[name], items)
		}
	}

	// пустые/мусорные секции не падают
	if len(parseFqdnGroups(nil)) != 0 || len(parseFqdnGroups("x")) != 0 {
		t.Error("garbage sections must produce empty result")
	}
}

func TestParseDnsProxyRoutes(t *testing.T) {
	dump := map[string]any{
		"dns-proxy": map[string]any{
			"route": []any{
				map[string]any{"group": "g1", "interface": "Wireguard1"},
				map[string]any{"group": "g2", "interface": "Wireguard2"},
			},
		},
	}
	got := parseDnsProxyRoutes(dump["dns-proxy"])
	if !got["g1"]["Wireguard1"] || !got["g2"]["Wireguard2"] || len(got) != 2 {
		t.Errorf("list form parse failed: %v", got)
	}

	// одиночный маршрут (объект, а не список)
	single := map[string]any{
		"dns-proxy": map[string]any{
			"route": map[string]any{"group": "g1", "interface": "Wireguard1"},
		},
	}
	if got := parseDnsProxyRoutes(single["dns-proxy"]); !got["g1"]["Wireguard1"] {
		t.Errorf("single form parse failed: %v", got)
	}

	// мусор не падает
	if len(parseDnsProxyRoutes(nil)) != 0 || len(parseDnsProxyRoutes(42)) != 0 {
		t.Error("garbage sections must produce empty result")
	}
}

func TestFormatItemList(t *testing.T) {
	if s := formatItemList([]string{"a", "b"}, 5); s != "a, b" {
		t.Errorf("got %q", s)
	}
	if s := formatItemList([]string{"a", "b", "c", "d"}, 2); s != "a, b и ещё 2" {
		t.Errorf("got %q", s)
	}
}
