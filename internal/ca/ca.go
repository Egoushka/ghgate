// Package ca owns ghgate's name-constrained certificate authority.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	certFile = "ca.pem"
	keyFile  = "ca.key"
	leafLife = 7 * 24 * time.Hour
)

type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreate loads the CA from dir, or generates it. The CA may sign only for hosts.
func LoadOrCreate(dir string, hosts []string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := requirePrivate(dir); err != nil {
		return nil, err
	}
	cp, kp := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	certPEM, cerr := os.ReadFile(cp)
	keyPEM, kerr := os.ReadFile(kp)
	if cerr == nil && kerr == nil {
		if err := requirePrivate(kp); err != nil {
			return nil, err
		}
		return parse(certPEM, keyPEM, hosts)
	}
	if !errors.Is(cerr, os.ErrNotExist) && cerr != nil {
		return nil, cerr
	}
	return create(cp, kp, hosts)
}

// requirePrivate refuses a path that group or others can access.
func requirePrivate(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ca: %s has mode %o; it must not be group- or world-accessible (chmod go-rwx)", path, fi.Mode().Perm())
	}
	return nil
}

func parse(certPEM, keyPEM []byte, hosts []string) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("ca: cannot decode ca.pem or ca.key")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	have := slices.Clone(cert.PermittedDNSDomains)
	want := slices.Clone(hosts)
	slices.Sort(have)
	slices.Sort(want)
	if len(cert.ExcludedIPRanges) < 2 || len(cert.ExcludedEmailAddresses) == 0 {
		return nil, errors.New("ca: existing CA predates the IP/email exclusions; delete ca.pem and ca.key to issue a new CA (clients must then trust it again)")
	}
	if !slices.Equal(have, want) {
		return nil, fmt.Errorf("ca: existing CA permits %v but intercept_hosts is %v; delete ca.pem and ca.key to issue a new CA (clients must then trust it again)", cert.PermittedDNSDomains, hosts)
	}
	return &CA{cert: cert, certPEM: certPEM, key: key, leaves: map[string]*tls.Certificate{}}, nil
}

func create(cp, kp string, hosts []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:                big.NewInt(now.UnixNano()),
		Subject:                     pkix.Name{CommonName: "ghgate CA", Organization: []string{"ghgate"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(5, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains:         hosts,
		PermittedDNSDomainsCritical: true,
		// Everything that is not a DNS name stays out of reach of a leaked key.
		ExcludedIPRanges:       []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
		ExcludedEmailAddresses: []string{""},
		ExcludedURIDomains:     []string{""},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	f, err := os.OpenFile(kp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Write(keyPEM); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cp, certPEM, 0o644); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, certPEM: certPEM, key: key, leaves: map[string]*tls.Certificate{}}, nil
}

func (c *CA) CertPEM() []byte { return c.certPEM }

func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Leaf returns a cached leaf certificate for host. It signs for any name it is
// asked for; the CA's name constraints, not this method, are the safeguard.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	return c.leaf(host, nil)
}

// leaf is Leaf with a hook to alter the template; only tests pass one, and they bypass the cache.
func (c *CA) leaf(host string, tweak func(*x509.Certificate)) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l := c.leaves[host]; tweak == nil && l != nil && time.Until(l.Leaf.NotAfter) > time.Hour {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if tweak != nil {
		tweak(tpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	if tweak == nil {
		c.leaves[host] = l
	}
	return l, nil
}
