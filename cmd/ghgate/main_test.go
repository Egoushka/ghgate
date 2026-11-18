package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthURLDialsLoopbackForWildcards(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8898":   "http://127.0.0.1:8898/healthz",
		":8898":          "http://127.0.0.1:8898/healthz",
		"[::]:8898":      "http://[::1]:8898/healthz",
		"127.0.0.1:8898": "http://127.0.0.1:8898/healthz",
		"10.1.2.3:9000":  "http://10.1.2.3:9000/healthz",
	} {
		got, err := healthURL(in)
		if err != nil || got != want {
			t.Fatalf("%s: got %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := healthURL("nonsense"); err == nil {
		t.Fatal("want an error for an address without a port")
	}
}

func TestHealthcheckExitsByStatus(t *testing.T) {
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	write := func(admin string) {
		os.WriteFile(cfgPath, []byte(`{"admin":"`+admin+`","clients":[{"name":"a","token_sha256":"`+strings.Repeat("0", 64)+`"}],"write":{"pat_env":"X"}}`), 0o600)
	}
	write(strings.TrimPrefix(srv.URL, "http://"))
	if err := healthcheck([]string{"--config", cfgPath}); err != nil {
		t.Fatalf("200 must pass: %v", err)
	}
	status = 503
	if err := healthcheck([]string{"--config", cfgPath}); err == nil {
		t.Fatal("503 must fail")
	}
	// wildcard admin address: dial loopback on the same port
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	status = 200
	write("0.0.0.0:" + port)
	if err := healthcheck([]string{"--config", cfgPath}); err != nil {
		t.Fatalf("wildcard admin: %v", err)
	}
	srv.Close()
	if err := healthcheck([]string{"--config", cfgPath}); err == nil {
		t.Fatal("a closed port must fail")
	}
}
