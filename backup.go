package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backupDir, _ := filepath.Abs(".")
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("ncmanager-backup-%s.zip", timestamp)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", backupName))

	zw := zip.NewWriter(w)
	defer zw.Close()

	files := []string{
		"data/config.json",
		"data/peers.json",
		"data/server_private.key",
		"data/.auth",
		"data/.secret",
		"data/.key",
		"presets/dns-routes.json",
	}
	for _, rel := range files {
		abs := filepath.Join(backupDir, rel)
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		if err := addToZip(zw, rel, abs); err != nil {
			log.Printf("backup: add %s: %v", rel, err)
		}
	}

	absWG := "/etc/wireguard"
	if entries, err := os.ReadDir(absWG); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			abs := filepath.Join(absWG, entry.Name())
			rel := filepath.Join("etc", "wireguard", entry.Name())
			if err := addToZip(zw, rel, abs); err != nil {
				log.Printf("backup: add %s: %v", rel, err)
			}
		}
	}

	absAmnezia := "/etc/amnezia/amneziawg"
	if entries, err := os.ReadDir(absAmnezia); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			abs := filepath.Join(absAmnezia, entry.Name())
			rel := filepath.Join("etc", "amnezia", "amneziawg", entry.Name())
			if err := addToZip(zw, rel, abs); err != nil {
				log.Printf("backup: add %s: %v", rel, err)
			}
		}
	}
}

func addToZip(zw *zip.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	_ = fi
	return nil
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "invalid multipart: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("backup")
	if err != nil {
		http.Error(w, "backup file required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		http.Error(w, "only .zip files are supported", http.StatusBadRequest)
		return
	}

	workingDir, _ := filepath.Abs(".")
	stat := header.Size
	body, _ := io.ReadAll(file)
	zr, err := zip.NewReader(bytes.NewReader(body), stat)
	if err != nil {
		http.Error(w, "invalid zip: "+err.Error(), http.StatusBadRequest)
		return
	}

	restored := []string{}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if strings.Contains(zf.Name, "..") {
			continue
		}
		target := filepath.Join(workingDir, filepath.FromSlash(zf.Name))
		rel, _ := filepath.Rel(workingDir, target)
		if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			log.Printf("restore: mkdir %s: %v", filepath.Dir(target), err)
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			log.Printf("restore: open %s: %v", zf.Name, err)
			continue
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			log.Printf("restore: create %s: %v", target, err)
			continue
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			log.Printf("restore: write %s: %v", target, err)
			continue
		}
		out.Close()
		rc.Close()
		restored = append(restored, zf.Name)
	}

	if len(restored) == 0 {
		http.Error(w, "no files restored", http.StatusBadRequest)
		return
	}

	downCmd := exec.Command("wg-quick", "down", wgConfigFile)
	downCmd.Stderr = io.Discard
	downCmd.CombinedOutput()

	amneziaEntries, _ := os.ReadDir("/etc/amnezia/amneziawg")
	for _, entry := range amneziaEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		exec.Command("awg-quick", "down", entry.Name()).CombinedOutput()
	}

	exec.Command("modprobe", "amneziawg").CombinedOutput()

	extractedWG := filepath.Join(workingDir, "etc", "wireguard", "wg0.conf")
	if data, err := os.ReadFile(extractedWG); err == nil {
		os.MkdirAll("/etc/wireguard", 0700)
		if err := writeFileAtomic("/etc/wireguard/wg0.conf", data); err != nil {
			log.Printf("restore: write wg0.conf: %v", err)
		}
	}

	extractedAmneziaDir := filepath.Join(workingDir, "etc", "amnezia", "amneziawg")
	var amneziaRestoreEntries []os.DirEntry
	if entries, err := os.ReadDir(extractedAmneziaDir); err == nil {
		os.MkdirAll("/etc/amnezia/amneziawg", 0700)
		amneziaRestoreEntries = entries
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			src := filepath.Join(extractedAmneziaDir, entry.Name())
			dst := filepath.Join("/etc/amnezia/amneziawg", entry.Name())
			if data, err := os.ReadFile(src); err == nil {
				if err := writeFileAtomic(dst, data); err != nil {
					log.Printf("restore: write %s: %v", dst, err)
				}
			}
		}
	}

	cfg, _ := loadConfig(dataFile)
	peersCfg, _ := loadPeers()
	if cfg != nil {
		if err := generateWgConfig(cfg, peersCfg.Peers); err != nil {
			log.Printf("restore: generate wg config: %v", err)
		}
	}
	if err := s.restartServerDirect(); err != nil {
		log.Printf("restore: restart wg: %v", err)
	}
	exec.Command("systemctl", "enable", "--now", "wg-quick@wg0").CombinedOutput()

	for _, entry := range amneziaRestoreEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		exec.Command("systemctl", "enable", "--now", "awg-quick@"+name).CombinedOutput()
		out, err := exec.Command("awg-quick", "up", name).CombinedOutput()
		if err != nil {
			log.Printf("restore: awg-quick up %s: %s", name, string(out))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
	})
}
