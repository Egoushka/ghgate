// Command ghgate is a forward proxy between AI agents and GitHub.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Egoushka/ghgate/internal/ca"
	"github.com/Egoushka/ghgate/internal/config"
	"github.com/Egoushka/ghgate/internal/proxy"
)

const usage = `usage:
  ghgate serve --config ghgate.json   run the proxy
  ghgate ca --config ghgate.json      print the CA certificate (PEM), creating it if needed
  ghgate healthcheck --config ghgate.json
                                      GET the admin /healthz; exit 0 on 200, else 1 (for a container with no shell)
  ghgate hash-token                   read a token on stdin, print its SHA-256`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "app-register":
		err = appRegister(os.Args[2:])
	case "ca":
		err = printCA(os.Args[2:])
	case "healthcheck":
		err = healthcheck(os.Args[2:])
	case "hash-token":
		err = hashToken(os.Stdin, os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghgate:", err)
		os.Exit(1)
	}
}

func loadConfig(args []string, name string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "ghgate.json", "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func serve(args []string) error {
	cfg, err := loadConfig(args, "serve")
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	s, err := proxy.New(cfg, proxy.Options{Logger: logger})
	if err != nil {
		return err
	}
	front := &http.Server{Addr: cfg.Listen, Handler: s, ReadHeaderTimeout: 30 * time.Second}
	admin := &http.Server{Addr: cfg.Admin, Handler: s.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- front.ListenAndServe() }()
	go func() { errc <- admin.ListenAndServe() }()
	logger.Info("listening", "proxy", cfg.Listen, "admin", cfg.Admin)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		admin.Shutdown(ctx)
		return front.Shutdown(ctx)
	}
}

func printCA(args []string) error {
	cfg, err := loadConfig(args, "ca")
	if err != nil {
		return err
	}
	c, err := ca.LoadOrCreateSet(cfg.StateDir, cfg.InterceptHosts)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(c.CertPEM())
	return err
}

func healthcheck(args []string) error {
	cfg, err := loadConfig(args, "healthcheck")
	if err != nil {
		return err
	}
	u, err := healthURL(cfg.Admin)
	if err != nil {
		return err
	}
	return checkHealth(u)
}

// healthURL dials loopback when admin listens on a wildcard address.
func healthURL(admin string) (string, error) {
	host, port, err := net.SplitHostPort(admin)
	if err != nil {
		return "", fmt.Errorf("admin address %q: %w", admin, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if ip != nil && ip.To4() == nil {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func checkHealth(url string) error {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

func hashToken(in io.Reader, out io.Writer) error {
	b, err := io.ReadAll(io.LimitReader(in, 1<<16))
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return fmt.Errorf("empty token on stdin")
	}
	sum := sha256.Sum256([]byte(tok))
	_, err = fmt.Fprintln(out, hex.EncodeToString(sum[:]))
	return err
}
