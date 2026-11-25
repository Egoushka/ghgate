package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// writerPerms is what a ghgate write App needs to act for every consumer; a client's own `perms` narrow it per token.
var writerPerms = map[string]string{
	"metadata": "read", "contents": "write", "pull_requests": "write", "issues": "write", "actions": "write",
	"workflows": "write", "checks": "write", "statuses": "write", "administration": "write", "packages": "read",
}

// appRegister runs GitHub's App manifest flow so the owner needs one browser visit: it serves a page whose button
// posts the manifest to GitHub, receives the redirect with a one-time code, converts it, and writes the private key
// to --key-out (0600). The key is never printed.
func appRegister(args []string) error {
	fs := flag.NewFlagSet("app-register", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8900", "address the owner's browser can reach")
	public := fs.String("url", "", "base URL the browser uses for --listen (default http://<listen>)")
	name := fs.String("name", "ghgate-writer", "App name")
	keyOut := fs.String("key-out", "", "file for the private key (PEM, 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyOut == "" {
		return fmt.Errorf("app-register: --key-out is required")
	}
	base := *public
	if base == "" {
		base = "http://" + *listen
	}
	st := make([]byte, 16)
	rand.Read(st)
	state := hex.EncodeToString(st)
	manifest, _ := json.Marshal(map[string]any{
		"name": *name, "url": "https://github.com/Egoushka/ghgate", "redirect_url": base + "/callback", "public": false,
		"hook_attributes": map[string]any{"url": "https://example.invalid/unused", "active": false}, "default_permissions": writerPerms,
	})
	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><form method="post" action="https://github.com/settings/apps/new?state=%s"><input type="hidden" name="manifest" value="%s"><button>Create the %s GitHub App</button></form>`,
			state, html.EscapeString(string(manifest)), html.EscapeString(*name))
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "bad state", http.StatusBadRequest)
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://api.github.com/app-manifests/"+r.URL.Query().Get("code")+"/conversions", nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
		}
		var out struct {
			ID      int64  `json:"id"`
			Slug    string `json:"slug"`
			PEM     string `json:"pem"`
			HTMLURL string `json:"html_url"`
		}
		if err == nil {
			if resp.StatusCode/100 != 2 {
				err = fmt.Errorf("conversion returned %d", resp.StatusCode)
			} else if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err == nil && out.PEM == "" {
				err = fmt.Errorf("conversion returned no key")
			}
		}
		if err == nil {
			err = os.WriteFile(*keyOut, []byte(out.PEM), 0o600)
		}
		if err != nil {
			http.Error(w, "app-register failed: "+err.Error(), http.StatusBadGateway)
			done <- err
			return
		}
		fmt.Printf("app id %d slug %s, key written to %s\n", out.ID, out.Slug, *keyOut)
		http.Redirect(w, r, "https://github.com/apps/"+out.Slug+"/installations/new", http.StatusSeeOther)
		done <- nil
	})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	fmt.Printf("open %s/ in a browser signed in to GitHub, click the button, then install the App on all repositories\n", base)
	err = <-done
	time.Sleep(time.Second) // let the redirect reach the browser
	srv.Shutdown(context.Background())
	return err
}
