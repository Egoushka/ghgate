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

func TestFailedInstallationLoadBacksOffFor60Seconds(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	var mu sync.Mutex
	loads := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		loads++
		mu.Unlock()
		w.WriteHeader(500)
	}))
	defer srv.Close()
	clock := time.Now()
	a := NewApp(1, keyFile, srv.URL, srv.Client())
	a.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	for i := 0; i < 5; i++ {
		if _, _, err := a.Token(context.Background(), "acme"); err == nil {
			t.Fatal("expected an error")
		}
	}
	mu.Lock()
	if loads != 1 {
		t.Fatalf("a failing /app/installations was called %d times in a row, want 1", loads)
	}
	clock = clock.Add(61 * time.Second)
	mu.Unlock()
	a.Token(context.Background(), "acme")
	mu.Lock()
	defer mu.Unlock()
	if loads != 2 {
		t.Fatalf("after the back-off it must try again: %d loads", loads)
	}
}

func TestAppWithoutOwnerHasNoInstallation(t *testing.T) {
	a := NewApp(1, "unused", "https://127.0.0.1:1", http.DefaultClient)
	if _, _, err := a.Token(context.Background(), ""); !errors.Is(err, ErrNoInstallation) {
		t.Fatalf("an empty owner must not pick an installation: %v", err)
	}
}

func testKeyPEM(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestKeyFromEnvAcceptsPEMAndBase64(t *testing.T) {
	key, p := testKeyPEM(t)
	t.Setenv("K_PEM", string(p))
	t.Setenv("K_B64", base64.StdEncoding.EncodeToString(p))
	t.Setenv("K_B64_NL", base64.StdEncoding.EncodeToString(p)+"\n")
	for _, n := range []string{"K_PEM", "K_B64", "K_B64_NL"} {
		k, err := KeyFromEnv(n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if !k.Equal(key) {
			t.Fatalf("%s: wrong key", n)
		}
	}
}

func TestKeyFromEnvErrorsNeverCarryTheValue(t *testing.T) {
	const secret = "SUPERSECRETVALUE"
	t.Setenv("K_BAD", secret+"!!")
	t.Setenv("K_NOTPEM", base64.StdEncoding.EncodeToString([]byte(secret)))
	t.Setenv("K_EMPTY", "  ")
	for _, n := range []string{"K_BAD", "K_NOTPEM", "K_EMPTY", "K_UNSET"} {
		_, err := KeyFromEnv(n)
		if err == nil {
			t.Fatalf("%s: want an error", n)
		}
		if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), n) {
			t.Fatalf("%s: error %q", n, err)
		}
	}
}

func TestAppWithEnvKeySignsAndPATFromEnvIsReadOnce(t *testing.T) {
	key, p := testKeyPEM(t)
	t.Setenv("K_PEM", string(p))
	k, err := KeyFromEnv("K_PEM")
	if err != nil {
		t.Fatal(err)
	}
	a := NewAppWithKey(5, k, "https://127.0.0.1:1", http.DefaultClient)
	j, err := a.jwt()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(j, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Fatal("jwt not signed by the env key:", err)
	}

	t.Setenv("GH_PAT_T", " ghp_env_token \n")
	pat, err := NewPATFromEnv("GH_PAT_T")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_PAT_T", "changed")
	tok, label, err := pat.Token(context.Background(), "o")
	if err != nil || tok != "ghp_env_token" || strings.Contains(label, tok) {
		t.Fatalf("tok=%q label=%q err=%v", tok, label, err)
	}
	if _, err := NewPATFromEnv("GH_PAT_UNSET"); err == nil || !strings.Contains(err.Error(), "GH_PAT_UNSET") {
		t.Fatalf("unset PAT env: %v", err)
	}
}

func TestInspectReportsPermissionsAndRepositoriesWithoutTheToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			fmt.Fprint(w, `[{"id":5,"account":{"login":"nytka-app"}}]`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			fmt.Fprintf(w, `{"token":"secret-tok","repository_selection":"selected","permissions":{"issues":"read","metadata":"read"},"expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case r.URL.Path == "/installation/repositories" && r.Header.Get("Authorization") == "Bearer secret-tok":
			fmt.Fprint(w, `{"repositories":[{"full_name":"nytka-app/server"},{"full_name":"nytka-app/android"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	got, err := NewApp(1, keyFile, srv.URL, srv.Client()).Inspect(context.Background(), "NYTKA-APP")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if got.Permissions["issues"] != "read" || len(got.Repos) != 2 || got.Selection != "selected" || strings.Contains(string(b), "secret-tok") {
		t.Fatalf("unexpected inspection %s", b)
	}
}
