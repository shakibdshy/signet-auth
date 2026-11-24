// Command gin demonstrates Signet with the Gin framework.
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

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/mailer/console"
	"github.com/shakibdshy/signet-auth/store/postgres"
)

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

const defaultDSN = "postgres://signet:signet@localhost:5432/signet?sslmode=disable"

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
	cfg.Store = store
	cfg.Mailer = console.New(os.Stdout) // development only
	cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
	cfg.CSRFKey = key
	cfg.AppURL = "http://localhost:8080"
	cfg.PathPrefix = "/auth"
	return signet.New(cfg)
}

func main() {
	auth, err := newAuth()
	if err != nil {
		log.Fatal(err)
	}
	router := gin.Default()
	router.Any("/auth/*path", gin.WrapH(auth.Handler()))
	router.GET("/private", gin.WrapH(auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := signet.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("hello " + user.Email))
	}))))
	server := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("listening on http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}
