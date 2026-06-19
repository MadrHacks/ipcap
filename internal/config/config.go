// Package config loads the shared AD infra configuration (vulnbox.yml,
// infra.yml) from the config directory, matching trafficsync/sync.py so the
// collector reuses the same Noise credentials and pcap directory, with mtime
// reload support.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultConfigDir mirrors trafficsync's AD_INFRA_CONFIG_DIR default.
const DefaultConfigDir = "/config"

// DefaultNoisePort is the agent's default Noise listener port.
const DefaultNoisePort = 7878

// Vulnbox is the subset of vulnbox.yml the collector needs to dial the agent's
// Noise listener: the (static) vulnbox IP, the listener port, and the agent's
// static public key, which the collector pins.
type Vulnbox struct {
	IP          string `yaml:"ip"`
	NoisePort   int    `yaml:"noise_port"`
	NoisePubKey string `yaml:"noise_pubkey"`
}

// Infra is the subset of infra.yml the collector needs.
type Infra struct {
	PcapDir string `yaml:"pcap_dir"`
}

// Port returns the Noise listener port, defaulting to DefaultNoisePort.
func (v Vulnbox) Port() int {
	if v.NoisePort == 0 {
		return DefaultNoisePort
	}
	return v.NoisePort
}

// ConfigDir resolves the config directory from the environment.
func ConfigDir() string {
	if d := os.Getenv("AD_INFRA_CONFIG_DIR"); d != "" {
		return d
	}
	return DefaultConfigDir
}

func loadYAML(dir, name string, out any) error {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return yaml.Unmarshal(b, out)
}

// Load reads vulnbox.yml and infra.yml from dir. A missing file yields zero
// values (the caller waits for the vulnbox IP to appear, like sync.py).
func Load(dir string) (Vulnbox, Infra, error) {
	var vb Vulnbox
	var infra Infra
	if err := loadYAML(dir, "vulnbox.yml", &vb); err != nil {
		return vb, infra, err
	}
	if err := loadYAML(dir, "infra.yml", &infra); err != nil {
		return vb, infra, err
	}
	if infra.PcapDir == "" {
		infra.PcapDir = "/var/log/ad-pcaps"
	}
	return vb, infra, nil
}

// Mtimes returns the modification times of the config files, for reload
// detection (mirrors sync.py's _config_mtimes).
func Mtimes(dir string) map[string]int64 {
	m := map[string]int64{}
	for _, name := range []string{"vulnbox.yml", "infra.yml"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil {
			m[name] = info.ModTime().UnixNano()
		} else {
			m[name] = 0
		}
	}
	return m
}

// MtimesEqual compares two mtime maps.
func MtimesEqual(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
