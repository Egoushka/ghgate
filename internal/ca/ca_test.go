package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestAC9_LeafVerifiesAndNameConstraintsHold(t *testing.T) {
	dir := t.TempDir()
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
	// reload keeps the same CA; changed hosts are refused
	c2, err := LoadOrCreate(dir, []string{"github.com", "api.github.com"})
	if err != nil || string(c2.CertPEM()) != string(c.CertPEM()) {
		t.Fatalf("reload: %v", err)
	}
	if _, err := LoadOrCreate(dir, []string{"github.com"}); err == nil {
		t.Fatal("changed intercept hosts must be refused")
	}
}
