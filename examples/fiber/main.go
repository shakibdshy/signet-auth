// Command fiber demonstrates Signet with Fiber, whose fasthttp server is
// bridged to net/http with Fiber's official adaptor middleware.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
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

func newAuth() (*signet.Client, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	store := postgres.New(pool)
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	cfg := signet.DefaultConfig()
	// Development convenience: skip email verification entirely.
	// Leave these unset (or true) in production.
	no := false
	cfg.RequireVerifiedEmail = &no
	cfg.SendVerificationOnSignUp = &no
	cfg.Store = store
	cfg.Mailer = console.New(os.Stdout) // development only
	cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
	cfg.CSRFKey = key
	cfg.AppURL = "http://localhost:8081"
	cfg.PathPrefix = "/auth"
	return signet.New(cfg)
}

func main() {
	auth, err := newAuth()
	if err != nil {
		log.Fatal(err)
	}
	app := fiber.New()
	app.All("/auth/*", adaptor.HTTPHandler(auth.Handler()))
	app.Get("/private",
		adaptor.HTTPMiddleware(auth.RequireAuth),
		adaptor.HTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := signet.UserFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("hello " + user.Email))
		}))
	log.Println("listening on http://localhost:8081")
	log.Fatal(app.Listen(":8081"))
}
