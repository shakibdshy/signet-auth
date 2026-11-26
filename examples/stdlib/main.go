// Command stdlib demonstrates Signet with the standard library router and a
// local PostgreSQL database.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/mailer/console"
	"github.com/shakibdshy/signet-auth/store/postgres"
)

const defaultDSN = "postgres://signet:signet@localhost:5432/signet?sslmode=disable"

type memoryLimiter struct {
	mu   sync.Mutex
	hits map[string]int
}

func (l *memoryLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key]++
	return l.hits[key] <= 10, nil
}

func databaseURL() string {
	if value := os.Getenv("SIGNET_DATABASE_URL"); value != "" {
		return value
	}
	return defaultDSN
}

// listenPort returns the port to serve on. Hosts like Render inject PORT;
// local development defaults to 8080.
func listenPort() string {
	if value := os.Getenv("PORT"); value != "" {
		return value
	}
	return "8080"
}

// appURL returns the public origin used in verification and reset links.
// Set APP_URL to the deployed origin; local development defaults to localhost.
func appURL(port string) string {
	if value := os.Getenv("APP_URL"); value != "" {
		return value
	}
	return "http://localhost:" + port
}

// csrfKey returns the 32-byte CSRF key. Set CSRF_KEY to a persistent base64
// key (`openssl rand -base64 32`) in production; regenerating it invalidates
// outstanding CSRF tokens. Without it a random key is generated per boot,
// which is fine for development only.
func csrfKey() []byte {
	if value := os.Getenv("CSRF_KEY"); value != "" {
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != 32 {
			log.Fatal("CSRF_KEY must be base64 and decode to exactly 32 bytes")
		}
		return key
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	return key
}

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("connect to PostgreSQL: %v", err)
	}
	store := postgres.New(pool)
	if err := store.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	port := listenPort()
	cfg := signet.DefaultConfig()
	// Development convenience: skip email verification entirely.
	// Leave these unset (or true) in production.
	no := false
	cfg.RequireVerifiedEmail = &no
	cfg.SendVerificationOnSignUp = &no
	cfg.Store = store
	cfg.Mailer = console.New(os.Stdout) // development only: prints links
	cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
	cfg.CSRFKey = csrfKey()
	cfg.AppURL = appURL(port)
	cfg.PathPrefix = "/auth"
	// Expose GET /auth/last-sign-in-method so frontends can show how the
	// current browser last signed in. Consent-gated via BeforeStore if needed.
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	auth, err := signet.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", landingHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/auth/", auth.Handler())
	mux.Handle("/private", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := signet.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s\n", user.Email)
	})))
	log.Println("listening on :" + port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
