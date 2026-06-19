package tls

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// OverrideTarget is a manually-specified target for when auto-detection misses
// (e.g. statically-linked Go services, or a library at a non-standard path).
type OverrideTarget struct {
	Container string `yaml:"container"` // label only, for logging
	Library   string `yaml:"library"`   // openssl | gnutls | gotls
	Path      string `yaml:"path"`      // host-visible library/binary path
	CGroup    string `yaml:"cgroup"`    // optional cgroup-v2 path to scope the hook
}

// Config is the live, operator-editable override file. It is reloaded on every
// reconcile so the infra operator can fix targeting mid-game without a restart.
type Config struct {
	// Auto enables /proc auto-discovery (default true when the file is absent or
	// the field is unset).
	Auto *bool `yaml:"auto"`
	// Exclude lists container-id prefixes or labels to NEVER hook — the safety
	// valve for a fragile vulnservice.
	Exclude []string `yaml:"exclude"`
	// Targets are manual additions/overrides.
	Targets []OverrideTarget `yaml:"targets"`
}

// LoadConfig reads the override file. A missing file yields auto-on defaults so
// the feature works with zero configuration.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// AutoEnabled reports whether auto-discovery is on (default true).
func (c Config) AutoEnabled() bool { return c.Auto == nil || *c.Auto }

// IsExcluded reports whether a target matches any exclude entry (by container-id
// prefix or substring match on the container label).
func (c Config) IsExcluded(t Target) bool {
	for _, ex := range c.Exclude {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		if strings.HasPrefix(t.Container, ex) || strings.Contains(t.Container, ex) {
			return true
		}
	}
	return false
}

// ManualTargets converts the override entries into Targets.
func (c Config) ManualTargets() []Target {
	out := make([]Target, 0, len(c.Targets))
	for i, o := range c.Targets {
		lib := Library(strings.ToLower(strings.TrimSpace(o.Library)))
		if lib != LibOpenSSL && lib != LibGnuTLS && lib != LibGoTLS {
			continue // skip malformed entries rather than fail the whole reconcile
		}
		container := o.Container
		if container == "" {
			container = "override"
		}
		key := container + "/" + string(lib)
		if o.Path != "" {
			key += "/" + o.Path
		}
		_ = i
		out = append(out, Target{
			Key:        key,
			Container:  container,
			Library:    lib,
			LibPath:    o.Path,
			CGroupPath: o.CGroup,
			Source:     "override",
		})
	}
	return out
}

// Plan merges auto-discovered and manual targets, drops excluded ones, and lets
// a manual target override an auto one with the same key.
func (c Config) Plan(auto []Target) []Target {
	merged := map[string]Target{}
	if c.AutoEnabled() {
		for _, t := range auto {
			if !c.IsExcluded(t) {
				merged[t.Key] = t
			}
		}
	}
	for _, t := range c.ManualTargets() {
		if !c.IsExcluded(t) {
			merged[t.Key] = t // manual wins on key collision
		}
	}
	out := make([]Target, 0, len(merged))
	for _, t := range merged {
		out = append(out, t)
	}
	return out
}
