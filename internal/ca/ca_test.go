package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newSet(t *testing.T) (*Set, string) {
	dir := filepath.Join(t.TempDir(), "state")
	set, err := LoadOrCreateSet(dir, []string{"api.github.com", "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	return set, dir
}

func verifies(c *CA, l *tls.Certificate, name string) error {
	_, err := l.Leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), DNSName: name})
	return err
}

func TestAC9_LeafVerifiesAndNameConstraintsHold(t *testing.T) {
	set, dir := newSet(t)
	for _, h := range []string{"api.github.com", "github.com"} {
		c := set.cas[h]
		if fi, _ := os.Stat(filepath.Join(dir, "ca", h, keyFile)); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s key mode %v", h, fi.Mode().Perm())
		}
		if !c.cert.PermittedDNSDomainsCritical || len(c.cert.PermittedDNSDomains) != 1 || c.cert.PermittedDNSDomains[0] != h {
			t.Fatalf("%s: name constraints wrong: %v", h, c.cert.PermittedDNSDomains)
		}
		good, _ := c.Leaf(h)
		if err := verifies(c, good, h); err != nil {
			t.Fatalf("%s leaf must verify: %v", h, err)
		}
	}
	gh := set.cas["github.com"]
	for _, name := range []string{"example.com", "evil.github.com", "api.github.com", "a.b.github.com", "notgithub.com"} {
		l, _ := gh.Leaf(name)
		if err := verifies(gh, l, name); err == nil {
			t.Errorf("a leaf for %s from the github.com CA must fail verification", name)
		}
	}
	api := set.cas["api.github.com"]
	if l, _ := api.Leaf("github.com"); verifies(api, l, "github.com") == nil {
		t.Error("the api.github.com CA must not sign github.com")
	}
	if l, _ := api.Leaf("x.api.github.com"); verifies(api, l, "x.api.github.com") == nil {
		t.Error("the api.github.com CA must not sign its subdomains")
	}
	// The bundle verifies each host and still rejects forgeries.
	l, _ := set.Leaf("github.com")
	if _, err := l.Leaf.Verify(x509.VerifyOptions{Roots: set.Pool(), DNSName: "github.com"}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(set.CertPEM()), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("ghgate ca must print every CA certificate")
	}
	// IP, email and URI names are excluded outright, even next to a permitted DNS name.
	for name, tweak := range map[string]func(*x509.Certificate){
		"ip":    func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.ParseIP("203.0.113.9")} },
		"ip6":   func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.ParseIP("2001:db8::1")} },
		"email": func(t *x509.Certificate) { t.EmailAddresses = []string{"a@github.com"} },
		"uri":   func(t *x509.Certificate) { t.URIs = []*url.URL{{Scheme: "https", Host: "github.com"}} },
	} {
		l, err := gh.leaf("github.com", tweak)
		if err != nil {
			t.Fatal(err)
		}
		if verifies(gh, l, "github.com") == nil {
			t.Errorf("a leaf with an extra %s name must fail verification", name)
		}
	}
	if _, err := set.Leaf("example.com"); err == nil {
		t.Fatal("Set must not issue for a host it does not intercept")
	}
	// reload keeps the same CAs; a changed host list adds a CA
	set2, err := LoadOrCreateSet(dir, []string{"github.com", "api.github.com"})
	if err != nil || string(set2.cas["github.com"].certPEM) != string(gh.certPEM) {
		t.Fatalf("reload: %v", err)
	}
}

func TestOldSingleCALayoutIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("old"), 0o644)
	_, err := LoadOrCreateSet(dir, []string{"github.com"})
	if err == nil || !strings.Contains(err.Error(), "old single-CA layout") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}

// OpenSSL must honour the constraints too, not only Go.
func TestOpenSSLHonoursPerHostConstraints(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("openssl is required in CI: the docs claim OpenSSL honours the constraints")
		}
		t.Skip("openssl not installed")
	}
	set, _ := newSet(t)
	tmp := t.TempDir()
	bundle := filepath.Join(tmp, "bundle.pem")
	os.WriteFile(bundle, set.CertPEM(), 0o644)
	gh := set.cas["github.com"]
	for _, c := range []struct {
		host string
		ok   bool
	}{{"github.com", true}, {"evil.github.com", false}, {"example.com", false}} {
		l, _ := gh.Leaf(c.host)
		f := filepath.Join(tmp, c.host+".pem")
		os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.Certificate[0]}), 0o644)
		out, err := exec.Command(ossl, "verify", "-CAfile", bundle, f).CombinedOutput()
		if (err == nil) != c.ok {
			t.Errorf("openssl verify %s: ok=%v want %v: %s", c.host, err == nil, c.ok, out)
		}
		t.Logf("openssl %s: %s", c.host, strings.TrimSpace(string(out)))
	}
}

func TestCARefusesOpenPermissions(t *testing.T) {
	hosts := []string{"github.com"}
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := LoadOrCreate(dir, hosts); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, keyFile), 0o644)
	if _, err := LoadOrCreate(dir, hosts); err == nil {
		t.Fatal("a world-readable key must be refused")
	}
	os.Chmod(filepath.Join(dir, keyFile), 0o600)
	os.Chmod(dir, 0o755)
	if _, err := LoadOrCreate(dir, hosts); err == nil {
		t.Fatal("a world-accessible state dir must be refused")
	}
	os.Chmod(dir, 0o700)
	if _, err := LoadOrCreate(dir, hosts); err != nil {
		t.Fatal(err)
	}
}

func TestCAKeyIs0600EvenUnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "s")
	os.MkdirAll(dir, 0o700)
	if _, err := LoadOrCreate(dir, []string{"github.com"}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ca.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}
