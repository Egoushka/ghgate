package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const goodHash = "0000000000000000000000000000000000000000000000000000000000000000"

func cfgWith(read, write *Cred) *Config {
	return &Config{Clients: []Client{{Name: "a", TokenSHA256: goodHash}}, Read: read, Write: write}
}

func TestCredentialSourceIsExactlyOne(t *testing.T) {
	ok := []*Cred{
		{PatFile: "/p"},
		{PatEnv: "GH_PAT"},
		{App: &App{ID: 1, KeyFile: "/k"}},
		{App: &App{ID: 1, KeyEnv: "GH_APP_KEY"}},
	}
	for i, c := range ok {
		if err := cfgWith(c, nil).Normalize(); err != nil {
			t.Fatalf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]*Cred{
		"none":             {},
		"file and env":     {PatFile: "/p", PatEnv: "X"},
		"pat and app":      {PatEnv: "X", App: &App{ID: 1, KeyEnv: "K"}},
		"app no key":       {App: &App{ID: 1}},
		"app file and env": {App: &App{ID: 1, KeyFile: "/k", KeyEnv: "K"}},
		"app no id":        {App: &App{KeyEnv: "K"}},
		"bad pat_env name": {PatEnv: "not a name"},
		"bad key_env name": {App: &App{ID: 1, KeyEnv: "1BAD"}},
	}
	for name, c := range bad {
		err := cfgWith(c, nil).Normalize()
		if err == nil || !strings.HasPrefix(err.Error(), "config:") {
			t.Fatalf("%s: want a config error, got %v", name, err)
		}
	}
}

func TestLoadParsesEnvFields(t *testing.T) {
	c := cfgWith(&Cred{PatEnv: "GH_READ"}, &Cred{App: &App{ID: 9, KeyEnv: "GH_KEY"}})
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if c.Read.PatEnv != "GH_READ" || c.Write.App.KeyEnv != "GH_KEY" {
		t.Fatal("env fields lost")
	}
}

func TestShippedExamplesLoad(t *testing.T) {
	ph := regexp.MustCompile(`<[^>"]*>`)
	for _, f := range []string{"ghgate.example.json", "ghgate.container.example.json"} {
		b, err := os.ReadFile("../../" + f)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, ph.ReplaceAll(b, []byte(goodHash)), 0o600)
		if _, err := Load(p); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}
