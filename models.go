package main

import (
	"sync"
	"time"
)

type amneziaTrafficEntry struct {
	points []amneziaTrafficSnapshot
}

type amneziaTrafficSnapshot struct {
	TS int64 `json:"ts"`
	Rx int64 `json:"rx"`
	Tx int64 `json:"tx"`
}

type PeersConfig struct {
	Peers []Peer `json:"peers"`
}

type Server struct {
	mu         sync.Mutex
	wgPort     int
	iface      string
	publicKey  string
	endpoint   string
	configPath string
}

type Peer struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	PublicKey      string    `json:"publicKey"`
	PrivateKey     string    `json:"privateKey"`
	CreatedAt      time.Time `json:"createdAt"`
	AllowedIPs     string    `json:"allowedIPs"`
	LastHandshake  time.Time `json:"lastHandshake,omitempty"`
	TransferRx     int64     `json:"transferRx"`
	TransferTx     int64     `json:"transferTx"`
	Endpoint       string    `json:"endpoint,omitempty"`
	RouterDomain   string    `json:"routerDomain,omitempty"`
	RouterLogin    string    `json:"routerLogin,omitempty"`
	RouterPassword string    `json:"routerPassword,omitempty"`
	Description    string    `json:"description,omitempty"`
	RouterIfName   string    `json:"routerIfName,omitempty"`
	Paid           bool      `json:"paid,omitempty"`
	VPNActive      bool      `json:"vpnActive,omitempty"`
	VPNOnly        bool      `json:"vpnOnly,omitempty"`
	Phone          string    `json:"phone,omitempty"`
}

// HasRouterCreds reports whether the peer has complete Keenetic router credentials.

// HasRouterCreds reports whether the peer has complete Keenetic router credentials.
func (p *Peer) HasRouterCreds() bool {
	return p.RouterDomain != "" && p.RouterLogin != "" && p.RouterPassword != ""
}

type Config struct {
	WGPort              int    `json:"wgPort"`
	HttpPort            int    `json:"httpPort"`
	Interface           string `json:"interface"`
	WanInterface        string `json:"wanInterface"`
	Endpoint            string `json:"endpoint"`
	DNS                 string `json:"dns"`
	Subnet              string `json:"subnet"`
	PostUp              string `json:"postUp,omitempty"`
	PostDown            string `json:"postDown,omitempty"`
	TLSEnabled          bool   `json:"tlsEnabled,omitempty"`
	TLSHost             string `json:"tlsHost,omitempty"`
	TLSCache            string `json:"tlsCache,omitempty"`
	TLSPort             int    `json:"tlsPort,omitempty"`
	TLSProvider         string `json:"tlsProvider,omitempty"`
	CloudflareToken     string `json:"cloudflareToken,omitempty"`
	CloudflareZone      string `json:"cloudflareZone,omitempty"`
	ServerName          string `json:"serverName,omitempty"`
	TelegramEnabled     bool   `json:"telegramEnabled,omitempty"`
	TelegramToken       string `json:"telegramToken,omitempty"`
	TelegramWelcome     string `json:"telegramWelcome,omitempty"`
	RouterCheckTimeout  int    `json:"routerCheckTimeout,omitempty"`
	RouterCheckInterval int    `json:"routerCheckInterval,omitempty"`
	RouterCacheTTL      int    `json:"routerCacheTTL,omitempty"`
}

type wgInfo struct {
	PublicKey  string
	ListenPort int
	Peers      []wgPeer
}

type wgPeer struct {
	PublicKey     string
	AllowedIPs    string
	LastHandshake time.Time
	TransferRx    int64
	TransferTx    int64
	Endpoint      string
}

type amneziaTrafficPoint struct {
	TS int64   `json:"ts"`
	Rx float64 `json:"rx"`
	Tx float64 `json:"tx"`
}

type amneziaTrafficStatsResponse struct {
	Points []amneziaTrafficPoint `json:"points"`
	Stats  amneziaTrafficStats   `json:"stats"`
}

type amneziaTrafficStats struct {
	Points    int64   `json:"points"`
	PeakRate  float64 `json:"peakRate"`
	AvgRx     float64 `json:"avgRx"`
	AvgTx     float64 `json:"avgTx"`
	CurrentRx float64 `json:"currentRx"`
	CurrentTx float64 `json:"currentTx"`
}

type amneziaConfigResponse struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	MTU        int    `json:"mtu"`
	DNS        string `json:"dns"`
	Endpoint   string `json:"endpoint"`
	PublicKey  string `json:"publicKey"`
	AllowedIPs string `json:"allowedIPs"`
	Keepalive  int    `json:"keepalive"`
	JC         int    `json:"jc"`
	JMIN       int    `json:"jmin"`
	JMAX       int    `json:"jmax"`
	S1         int    `json:"s1"`
	S2         int    `json:"s2"`
	S3         int    `json:"s3"`
	S4         int    `json:"s4"`
	H1         string `json:"h1"`
	H2         string `json:"h2"`
	H3         string `json:"h3"`
	H4         string `json:"h4"`
	I1         string `json:"i1"`
	I2         string `json:"i2"`
	I3         string `json:"i3"`
	I4         string `json:"i4"`
	I5         string `json:"i5"`
	Table      string `json:"table"`
}
