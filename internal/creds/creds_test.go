package creds

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAC11_AppMintsPerOwnerAndRenewsBeforeExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)

	var mu sync.Mutex
	mints := map[string]int{}
	clock := time.Now()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := verifyJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &key.PublicKey, 777, clock); err != nil {
			t.Errorf("bad app jwt on %s: %v", r.URL.Path, err)
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/app/installations":
			fmt.Fprint(w, `[{"id":1,"account":{"login":"Acme"}},{"id":2,"account":{"login":"globex"}}]`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			id := strings.Split(r.URL.Path, "/")[3]
			mints[id]++
			fmt.Fprintf(w, `{"token":"tok-%s-%d","expires_at":%q}`, id, mints[id], clock.Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	a := NewApp(777, keyFile, srv.URL, srv.Client())
	a.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	ctx := context.Background()
	tok := func(owner string) string {
		tk, _, err := a.Token(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		return tk
	}
	if tok("acme") != "tok-1-1" || tok("globex") != "tok-2-1" {
		t.Fatal("one token per owner expected")
	}
	if tok("ACME") != "tok-1-1" {
		t.Fatal("owner match is case-insensitive and the token is reused")
	}
	mu.Lock()
	clock = clock.Add(49 * time.Minute) // 11 minutes before expiry: still valid
	mu.Unlock()
	if tok("acme") != "tok-1-1" {
		t.Fatal("renewed too early")
	}
	mu.Lock()
	clock = clock.Add(2 * time.Minute) // 9 minutes before expiry: renew
	mu.Unlock()
	if tok("acme") != "tok-1-2" {
		t.Fatal("not renewed 10 minutes before expiry")
	}
	if _, _, err := a.Token(ctx, "nobody"); !errors.Is(err, ErrNoInstallation) {
		t.Fatalf("unknown owner: %v", err)
	}
}

func verifyJWT(tok string, pub *rsa.PublicKey, iss int64, now time.Time) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("not a jwt")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return err
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var hdr struct{ Alg string }
	var pl struct{ Iat, Exp, Iss int64 }
	json.Unmarshal(hb, &hdr)
	json.Unmarshal(pb, &pl)
	if hdr.Alg != "RS256" || pl.Iss != iss || pl.Exp-pl.Iat > 600 || pl.Exp < now.Unix() {
		return fmt.Errorf("bad claims %+v %+v", hdr, pl)
	}
	return nil
}

func TestAC12_PATReloadsOnMtimeChange(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pat")
	os.WriteFile(f, []byte("one\n"), 0o600)
	p := NewPAT(f)
	if tk, _, _ := p.Token(context.Background(), ""); tk != "one" {
		t.Fatal(tk)
	}
	os.WriteFile(f, []byte("two\n"), 0o600)
	later := time.Now().Add(3 * time.Second)
	os.Chtimes(f, later, later)
	if tk, _, _ := p.Token(context.Background(), ""); tk != "two" {
		t.Fatal("rotation not picked up")
	}
}

func TestAppMintDoesNotBlockOtherOwnersAndIsShared(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	var mu sync.Mutex
	mints := map[string]int{}
	slow := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			fmt.Fprint(w, `[{"id":1,"account":{"login":"acme"}},{"id":2,"account":{"login":"globex"}}]`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			id := strings.Split(r.URL.Path, "/")[3]
			mu.Lock()
			mints[id]++
			mu.Unlock()
			if id == "1" {
				<-slow
			}
			fmt.Fprintf(w, `{"token":"tok-%s","expires_at":%q}`, id, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		}
	}))
	defer srv.Close()
	a := NewApp(1, keyFile, srv.URL, srv.Client())
	ctx := context.Background()
	if tk, _, err := a.Token(ctx, "globex"); err != nil || tk != "tok-2" {
		t.Fatal(tk, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ { // ten callers for a slow owner share one mint
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tk, _, err := a.Token(ctx, "acme"); err != nil || tk != "tok-1" {
				t.Error(tk, err)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	done := make(chan string, 1)
	go func() { tk, _, _ := a.Token(ctx, "globex"); done <- tk }()
	select {
	case tk := <-done:
		if tk != "tok-2" {
			t.Fatal(tk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cached owner's token is blocked behind another owner's slow mint")
	}
	close(slow)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if mints["1"] != 1 || mints["2"] != 1 {
		t.Fatalf("mints %v", mints)
	}
}
