package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func createDefaultConfig() (*Config, error) {
	priv, _, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key pair: %w", err)
	}
	cfg := &Config{
		WGPort:    51820,
		HttpPort:  8080,
		Interface: "wg0",
		Endpoint:  getPublicIP(),
		DNS:       "1.1.1.1",
		Subnet:    "10.0.0.0/24",
	}
	if err := os.MkdirAll(filepath.Dir(serverPrivateKeyFile), 0700); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}
	if err := savePrivateKey(serverPrivateKeyFile, priv); err != nil {
		return nil, fmt.Errorf("failed to save server private key: %w", err)
	}
	return cfg, nil
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(cfg)
}

func loadPeers() (*PeersConfig, error) {
	f, err := os.Open(peersFile)
	if err != nil {
		return &PeersConfig{Peers: []Peer{}}, nil
	}
	defer f.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return &PeersConfig{Peers: []Peer{}}, nil
	}
	var pc PeersConfig
	if err := json.Unmarshal(raw["peers"], &pc.Peers); err != nil {
		return &PeersConfig{Peers: []Peer{}}, nil
	}
	if pc.Peers == nil {
		pc.Peers = []Peer{}
	}
	for i := range pc.Peers {
		if pc.Peers[i].RouterPassword != "" {
			if plain, ok := DecryptPassword(pc.Peers[i].RouterPassword); ok {
				pc.Peers[i].RouterPassword = plain
			}
		}
	}
	if _, hasDns := raw["dnsRoutes"]; hasDns {
		delete(raw, "dnsRoutes")
		_ = savePeers(&pc)
	}
	return &pc, nil
}

func savePeers(pc *PeersConfig) error {
	if err := os.MkdirAll(filepath.Dir(peersFile), 0755); err != nil {
		return err
	}
	f, err := os.Create(peersFile)
	if err != nil {
		return err
	}
	defer f.Close()
	// Шифруем копию среза, чтобы не мутировать переданный конфиг:
	// вызывающий код продолжает работать с открытыми паролями.
	out := *pc
	out.Peers = make([]Peer, len(pc.Peers))
	for i := range pc.Peers {
		out.Peers[i] = pc.Peers[i]
		if out.Peers[i].RouterPassword != "" {
			out.Peers[i].RouterPassword = EncryptPassword(out.Peers[i].RouterPassword)
		}
	}
	return json.NewEncoder(f).Encode(&out)
}

func loadDnsRoutes() ([]DnsRoute, error) {
	if _, err := os.Stat(dnsRoutesFile); err == nil {
		f, err := os.Open(dnsRoutesFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var routes []DnsRoute
		if err := json.NewDecoder(f).Decode(&routes); err != nil {
			return nil, err
		}
		if routes == nil {
			return []DnsRoute{}, nil
		}
		return routes, nil
	}

	f, err := os.Open(peersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []DnsRoute{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return []DnsRoute{}, nil
	}

	var migrated []DnsRoute
	if rawDns, ok := raw["dnsRoutes"]; ok && len(rawDns) > 0 && string(rawDns) != "null" {
		_ = json.Unmarshal(rawDns, &migrated)
	}
	if len(migrated) > 0 {
		_ = saveDnsRoutes(migrated)
	}
	return migrated, nil
}

func saveDnsRoutes(routes []DnsRoute) error {
	if err := os.MkdirAll(filepath.Dir(dnsRoutesFile), 0755); err != nil {
		return err
	}
	f, err := os.Create(dnsRoutesFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if routes == nil {
		routes = []DnsRoute{}
	}
	return json.NewEncoder(f).Encode(routes)
}

func configureUfwRoutes(cfg *Config) error {
	if cfg.WanInterface == "" {
		return nil
	}
	vpnIface := cfg.Interface
	if vpnIface == "" {
		vpnIface = "wg0"
	}
	cmds := [][]string{
		{"ufw", "route", "allow", "in", "on", vpnIface, "out", "on", cfg.WanInterface},
		{"ufw", "route", "allow", "in", "on", cfg.WanInterface, "out", "on", vpnIface},
	}
	for _, args := range cmds {
		if out, err := execWithTimeout(10*time.Second, args[0], args[1:]...); err != nil {
			return fmt.Errorf("ufw %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
