package ca

import (
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAC9_LeafVerifiesAndNameConstraintsHold(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	c, err := LoadOrCreate(dir, []string{"api.github.com", "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, keyFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	if !c.cert.PermittedDNSDomainsCritical || len(c.cert.PermittedDNSDomains) != 2 {
		t.Fatal("name constraints missing or not critical")
	}
	good, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: c.Pool(), DNSName: "api.github.com"}
	if _, err := good.Leaf.Verify(opts); err != nil {
		t.Fatalf("api.github.com leaf must verify: %v", err)
	}
	bad, err := c.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), DNSName: "example.com"}); err == nil {
		t.Fatal("a leaf for example.com must fail verification")
	}
	// The known limit: a DNS constraint covers subdomains, so a leaked key can forge *.github.com.
	sub, _ := c.Leaf("evil.github.com")
	if _, err := sub.Leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), DNSName: "evil.github.com"}); err != nil {
		t.Fatalf("documented limit changed: evil.github.com is expected to verify: %v", err)
	}
	// IP and email names are excluded outright, even next to a permitted DNS name.
	for name, tweak := range map[string]func(*x509.Certificate){
		"ip":    func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.ParseIP("203.0.113.9")} },
		"ip6":   func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.ParseIP("2001:db8::1")} },
		"email": func(t *x509.Certificate) { t.EmailAddresses = []string{"a@github.com"} },
		"uri":   func(t *x509.Certificate) { t.URIs = []*url.URL{{Scheme: "https", Host: "github.com"}} },
	} {
		l, err := c.leaf("api.github.com", tweak)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), DNSName: "api.github.com"}); err == nil {
			t.Errorf("a leaf with an extra %s name must fail verification", name)
		}
	}
	// reload keeps the same CA; changed hosts are refused
	c2, err := LoadOrCreate(dir, []string{"github.com", "api.github.com"})
	if err != nil || string(c2.CertPEM()) != string(c.CertPEM()) {
		t.Fatalf("reload: %v", err)
	}
	if _, err := LoadOrCreate(dir, []string{"github.com"}); err == nil {
		t.Fatal("changed intercept hosts must be refused")
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
