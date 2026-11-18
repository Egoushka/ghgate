// Package config loads and validates ghgate's JSON configuration.
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Client struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	CanWrite    bool   `json:"can_write"`
}

type App struct {
	ID      int64  `json:"id"`
	KeyFile string `json:"key_file"`
}

type Cred struct {
	PatFile string `json:"pat_file,omitempty"`
	App     *App   `json:"app,omitempty"`
}

type Config struct {
	Listen         string   `json:"listen"`
	Admin          string   `json:"admin"`
	StateDir       string   `json:"state_dir"`
	InterceptHosts []string `json:"intercept_hosts"`
	TunnelOthers   *bool    `json:"tunnel_others"`
	Clients        []Client `json:"clients"`
	Read           *Cred    `json:"read"`
	Write          *Cred    `json:"write"`
	CacheMB        int      `json:"cache_mb"`
	MaxEntryMB     int      `json:"max_entry_mb"`
	MaxBuffers     int      `json:"max_inflight_buffers"`
	FreshForMS     int      `json:"fresh_for_ms"`
	Floor          int      `json:"floor"`
	WriteFloor     int      `json:"write_floor"`
	// UpstreamAPI and UpstreamWeb override where api.github.com and github.com
	// are really reached; tests point them at httptest servers.
	UpstreamAPI string `json:"upstream_api"`
	UpstreamWeb string `json:"upstream_web"`
}

func (c *Config) TunnelOthersOn() bool { return c.TunnelOthers != nil && *c.TunnelOthers }

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Normalize(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Normalize fills defaults and validates.
func (c *Config) Normalize() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8899"
	}
	if c.Admin == "" {
		c.Admin = "127.0.0.1:8898"
	}
	if c.StateDir == "" {
		c.StateDir = "state"
	}
	if len(c.InterceptHosts) == 0 {
		c.InterceptHosts = []string{"api.github.com", "github.com"}
	}
	for i, h := range c.InterceptHosts {
		c.InterceptHosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	if c.CacheMB <= 0 {
		c.CacheMB = 256
	}
	if c.MaxEntryMB <= 0 {
		c.MaxEntryMB = 8
	}
	if c.MaxBuffers <= 0 {
		c.MaxBuffers = 64
	}
	if c.Floor == 0 {
		c.Floor = 300
	}
	if c.WriteFloor == 0 {
		c.WriteFloor = 50
	}
	if c.Write == nil && c.Read == nil {
		return errors.New("config: at least one of read or write credentials is required")
	}
	if c.Write == nil {
		c.Write = c.Read
	}
	if c.Read == nil {
		c.Read = c.Write
	}
	for _, cr := range []*Cred{c.Read, c.Write} {
		if (cr.PatFile == "") == (cr.App == nil) {
			return errors.New("config: a credential needs exactly one of pat_file or app")
		}
		if cr.App != nil && (cr.App.ID == 0 || cr.App.KeyFile == "") {
			return errors.New("config: app needs id and key_file")
		}
	}
	if len(c.Clients) == 0 {
		return errors.New("config: at least one client is required")
	}
	for _, cl := range c.Clients {
		b, err := hex.DecodeString(cl.TokenSHA256)
		if cl.Name == "" || err != nil || len(b) != 32 {
			return fmt.Errorf("config: client %q needs a name and a 64-hex token_sha256", cl.Name)
		}
	}
	return nil
}
