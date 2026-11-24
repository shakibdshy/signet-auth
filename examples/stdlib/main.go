// Command stdlib demonstrates Signet with the standard library router and a
// local PostgreSQL database.
package main

import (
	"context"
	"crypto/rand"
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

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	cfg := signet.DefaultConfig()
	// Development convenience: skip email verification entirely.
	// Leave these unset (or true) in production.
	no := false
	cfg.RequireVerifiedEmail = &no
	cfg.SendVerificationOnSignUp = &no
	cfg.Store = store
	cfg.Mailer = console.New(os.Stdout) // development only: prints links
	cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
	cfg.CSRFKey = key
	cfg.AppURL = "http://localhost:8080"
	cfg.PathPrefix = "/auth"
	auth, err := signet.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", auth.Handler())
	mux.Handle("/private", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := signet.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s\n", user.Email)
	})))
	log.Println("listening on http://localhost:8080")
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
