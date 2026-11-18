// Package creds supplies upstream GitHub tokens: PAT files and GitHub App installation tokens.
package creds

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNoInstallation means the GitHub App is not installed on the owner.
var ErrNoInstallation = errors.New("creds: app is not installed on this owner")

// Source hands out a token for requests about owner. Label names the rate-limit
// bucket the token draws on; it never contains the token.
type Source interface {
	Token(ctx context.Context, owner string) (token, label string, err error)
}

// PAT reads a personal access token from a file and re-reads it when the file changes.
type PAT struct {
	path string

	mu    sync.Mutex
	mtime time.Time
	size  int64
	tok   string
}

func NewPAT(path string) *PAT { return &PAT{path: path} }

func (p *PAT) Token(_ context.Context, _ string) (string, string, error) {
	fi, err := os.Stat(p.path)
	if err != nil {
		return "", "", errors.New("creds: cannot stat pat file")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tok == "" || !fi.ModTime().Equal(p.mtime) || fi.Size() != p.size {
		b, err := os.ReadFile(p.path)
		if err != nil {
			return "", "", errors.New("creds: cannot read pat file")
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", "", errors.New("creds: pat file is empty")
		}
		p.tok, p.mtime, p.size = tok, fi.ModTime(), fi.Size()
	}
	return p.tok, "pat:" + p.path, nil
}

// StaticPAT is a token read once, from the environment, at start.
type StaticPAT struct {
	tok, label string
}

// NewPATFromEnv reads the token from the variable name. Errors never include the value.
func NewPATFromEnv(name string) (*StaticPAT, error) {
	tok := strings.TrimSpace(os.Getenv(name))
	if tok == "" {
		return nil, fmt.Errorf("creds: environment variable %s is empty or unset", name)
	}
	return &StaticPAT{tok: tok, label: "pat:env:" + name}, nil
}

func (p *StaticPAT) Token(_ context.Context, _ string) (string, string, error) {
	return p.tok, p.label, nil
}
