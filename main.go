package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	initAuth()
	initAuthSecret()
	InitEncryptionKey()
	initLogger()
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("Warning: could not create log dir %s: %v", logDir, err)
	}

	server := &Server{
		wgPort:     51820,
		iface:      "wg0",
		endpoint:   getPublicIP(),
		configPath: absPath(wgConfigFile),
	}

	cfg, err := loadConfig(dataFile)
	if err != nil {
		log.Printf("No config found, creating default: %v", err)
		cfg, err = createDefaultConfig()
		if err != nil {
			log.Fatalf("failed to create default config: %v", err)
		}
		if err := saveConfig(dataFile, cfg); err != nil {
			log.Fatalf("failed to save default config: %v", err)
		}
	}
	server.endpoint = resolveEndpoint(cfg.Endpoint)
	if cfg.RouterCacheTTL > 0 {
		setRouterCacheTTLSeconds(cfg.RouterCacheTTL)
	}

	if cfg.HttpPort == 0 {
		cfg.HttpPort = 8080
		_ = saveConfig(dataFile, cfg)
	}

	if cfg.WanInterface == "" {
		cfg.WanInterface = detectDefaultWan()
		_ = saveConfig(dataFile, cfg)
	}

	peersCfg, err := loadPeers()
	if err != nil {
		log.Printf("No peers config found, using empty: %v", err)
		peersCfg = &PeersConfig{Peers: []Peer{}}
	}

	if err := generateWgConfig(cfg, peersCfg.Peers); err != nil {
		log.Printf("Warning: could not generate wg config on startup: %v", err)
	}

	syncServerKeyFromRunning()

	if _, statErr := os.Stat(wgConfigFile); statErr == nil {
		if _, showErr := execWithTimeout(5*time.Second, "wg", "show", "wg0"); showErr != nil {
			out, upErr := execWithTimeout(30*time.Second, "wg-quick", "up", wgConfigFile)
			if upErr != nil {
				log.Printf("wg-quick up failed: %s", strings.TrimSpace(string(out)))
			} else {
				log.Printf("wg0 started on startup")
			}
		} else {
			if getActualServerPrivateKey() == "" {
				privBytes, perr := loadPrivateKey(serverPrivateKeyFile)
				if perr == nil && len(strings.TrimSpace(string(privBytes))) == 44 {
					if kerr := applyServerPrivateKey(strings.TrimSpace(string(privBytes))); kerr != nil {
						log.Printf("wg0 running but keyless, re-apply failed: %v", kerr)
					} else {
						log.Printf("wg0 running but keyless, private key re-applied")
					}
				} else {
					log.Printf("wg0 running but keyless, no stored key to re-apply")
				}
			}
			if cfgBytes, rerr := os.ReadFile(wgConfigFile); rerr == nil {
				if tmpName, terr := wgSyncTempFile(toSyncconfConfig(string(cfgBytes))); terr == nil {
					out, serr := execWithTimeout(10*time.Second, "wg", "syncconf", "wg0", tmpName)
					if serr != nil {
						log.Printf("wg0 running, peer resync failed: %v, output: %s", serr, string(out))
					} else {
						log.Printf("wg0 running, peers synced from config")
					}
					os.Remove(tmpName)
				}
			} else {
				log.Printf("wg0 already running, config regenerated but interface kept")
			}
		}
	}

	http.HandleFunc("/", serveIndex)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	api := http.NewServeMux()
	api.HandleFunc("/version", server.getVersion)
	api.HandleFunc("/status", withAuth(server.getStatus))
	api.HandleFunc("/config", withAuth(server.getConfig))
	api.HandleFunc("/config/save", withAuth(server.saveConfig))
	api.HandleFunc("/config/save/general", withAuth(server.saveGeneralConfig))
	api.HandleFunc("/interfaces", withAuth(server.listInterfaces))
	api.HandleFunc("/peers", withAuth(server.listPeers))
	api.HandleFunc("/peers/add", withAuth(server.addPeer))
	api.HandleFunc("/peers/remove", withAuth(server.removePeer))
	api.HandleFunc("/peers/update", withAuth(server.updatePeer))
	api.HandleFunc("/peers/qrcode/", withAuth(server.getPeerQR))
	api.HandleFunc("/peers/config/", withAuth(server.getPeerConfigText))
	api.HandleFunc("/peers/download/", withAuth(server.downloadPeerConfig))
	api.HandleFunc("/peers/keenetic/", withAuth(server.importPeerToKeenetic))
	api.HandleFunc("/peers/keenetic-dl/", withAuth(server.downloadPeerKeeneticConfig))
	api.HandleFunc("/peers/keenetic-dns/", withAuth(server.configurePeerDns))
	api.HandleFunc("/peers/keenetic-dns-routes/", withAuth(server.configurePeerDnsRoutes))
	api.HandleFunc("/peers/keenetic-components/", withAuth(server.configurePeerComponents))
	api.HandleFunc("/peers/keenetic-apply/", withAuth(server.applyPeerVpn))
	api.HandleFunc("/peers/keenetic-remove/", withAuth(server.removePeerVpn))
	api.HandleFunc("/peers/keenetic-status/", withAuth(server.getPeerVpnStatus))
	api.HandleFunc("/components/apply", withAuth(server.configurePeerComponents))
	api.HandleFunc("/components/apply/status", withAuth(server.getComponentsApplyStatus))
	api.HandleFunc("/dns/routes", withAuth(server.listDnsRoutes))
	api.HandleFunc("/dns/routes/create", withAuth(server.createDnsRoute))
	api.HandleFunc("/dns/routes/update", withAuth(server.updateDnsRoute))
	api.HandleFunc("/dns/routes/delete", withAuth(server.deleteDnsRoute))
	api.HandleFunc("/dns/routes/export", withAuth(server.exportDnsRoutes))
	api.HandleFunc("/dns/routes/import", withAuth(server.importDnsRoutes))
	api.HandleFunc("/dns/routes/apply", withAuth(server.applyDnsRoutesToRouter))
	api.HandleFunc("/dns/apply/status", withAuth(server.getDnsApplyStatus))
	api.HandleFunc("/presets/dns-routes", withAuth(server.getDnsRoutePresets))
	api.HandleFunc("/server/start", withAuth(server.startServer))
	api.HandleFunc("/server/stop", withAuth(server.stopServer))
	api.HandleFunc("/server/restart", withAuth(server.restartServer))
	api.HandleFunc("/server/restart-service", withAuth(server.restartService))
	api.HandleFunc("/keys/generate", withAuth(generateKeys))
	api.HandleFunc("/login", loginHandler)
	api.HandleFunc("/logout", withAuth(logoutHandler))
	api.HandleFunc("/auth/change-password", withAuth(changePasswordHandler))
	api.HandleFunc("/logs", withAuth(server.getLogs))
	api.HandleFunc("/https/status", withAuth(server.getHttpsStatus))
	api.HandleFunc("/https/apply", withAuth(server.applyHttps))
	api.HandleFunc("/router/dump/", withAuth(server.dumpRouterRCI))
	api.HandleFunc("/amnezia/status", withAuth(server.getAmneziaStatus))
	api.HandleFunc("/amnezia/install", withAuth(server.installAmnezia))
	api.HandleFunc("/amnezia/import", withAuth(server.importAmneziaConfig))
	api.HandleFunc("/amnezia/interfaces", withAuth(server.getAmneziaInterfaces))
	api.HandleFunc("/amnezia/interface/", withAuth(server.handleAmneziaInterface))
	api.HandleFunc("/backup/create", withAuth(server.createBackup))
	api.HandleFunc("/backup/restore", withAuth(server.restoreBackup))
	api.HandleFunc("/peers/router-info/", withAuth(server.getPeerRouterInfo))
	api.HandleFunc("/peers/router-check/", withAuth(server.checkPeerRouter))
	http.Handle("/api/", http.StripPrefix("/api", api))

	initHTTPS()

	go startAmneziaTrafficPoller()
	go startAmneziaTrafficCleanup()

	addr := fmt.Sprintf(":%d", cfg.HttpPort)
	log.Printf("NC Manager starting on %s", addr)
	log.Printf("Endpoint: %s", server.endpoint)
	log.Printf("Version: %s", appVersion)
	log.Fatal(http.ListenAndServe(addr, nil))
}
