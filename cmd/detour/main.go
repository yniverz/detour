// Command detour is a header-routed reverse proxy: a trusted front proxy tells it,
// per request, which upstream(s) to forward to.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yniverz/detour/internal/config"
	"github.com/yniverz/detour/internal/proxy"
	"github.com/yniverz/detour/internal/selfsigned"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println(version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		case "help", "-h", "--help":
			fmt.Println("detour - header-routed reverse proxy\n\nUsage:\n  detour              run the proxy (configured via DETOUR_* environment variables)\n  detour healthcheck  exit 0 if the running instance is healthy\n  detour version      print the version\n\nSee https://github.com/yniverz/detour for configuration.")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "detour:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	log := newLogger(cfg)

	srv, err := proxy.New(cfg, log)
	if err != nil {
		return err
	}
	if cfg.AuthDisabled {
		log.Warn("authentication disabled (DETOUR_AUTH_DISABLED=true)", "trusted_sources", cfg.TrustedSources)
	}
	if cfg.AllowAnyTarget {
		log.Warn("any upstream target allowed (DETOUR_ALLOW_ANY_TARGET=true)")
	}

	proxyServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.TLSSelfSigned {
		hosts := cfg.TLSSelfSigHosts
		if len(hosts) == 0 {
			hosts = selfsigned.DefaultHosts()
		}
		cert, err := selfsigned.Generate(hosts, time.Now())
		if err != nil {
			return fmt.Errorf("generating self-signed certificate: %w", err)
		}
		proxyServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		log.Info("generated self-signed certificate", "names", selfsigned.Describe(cert), "sha256", selfsigned.Fingerprint(cert))
	}
	servers := []*http.Server{proxyServer}

	if cfg.AdminListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok\n"))
		})
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			srv.Metrics.WriteTo(w, srv.DownCount())
		})
		servers = append(servers, &http.Server{
			Addr:              cfg.AdminListen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		})
	}

	errc := make(chan error, len(servers))
	for i, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		tlsOn := i == 0 && cfg.TLSEnabled()
		log.Info("listening", "addr", ln.Addr().String(), "role", map[bool]string{true: "proxy", false: "admin"}[i == 0], "tls", tlsOn, "version", version)
		go func(s *http.Server, ln net.Listener, tlsOn bool) {
			var err error
			if tlsOn {
				err = s.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile) // empty paths use TLSConfig.Certificates
			} else {
				err = s.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s, ln, tlsOn)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// healthcheck probes the admin /healthz endpoint if configured, otherwise it
// checks that the proxy port accepts connections.
func healthcheck() int {
	admin := os.Getenv("DETOUR_ADMIN_LISTEN")
	if admin != "" {
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://" + loopback(admin) + "/healthz")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 1
		}
		return 0
	}
	listen := os.Getenv("DETOUR_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	conn, err := net.DialTimeout("tcp", loopback(listen), 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn.Close()
	return 0
}

// loopback turns ":8080" or "0.0.0.0:8080" into "127.0.0.1:8080".
func loopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "[::]") {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
