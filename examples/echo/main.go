// Command echo demonstrates Signet with the Echo framework.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	_ "modernc.org/sqlite"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/mailer/console"
	"github.com/shakibdshy/signet/store/sqlite"
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

func newAuth() (*signet.Client, error) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "signet.db")
	if err != nil {
		return nil, err
	}
	store := sqlite.New(db)
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
	return signet.New(cfg)
}

func main() {
	auth, err := newAuth()
	if err != nil {
		log.Fatal(err)
	}
	e := echo.New()
	e.Any("/auth/*", echo.WrapHandler(auth.Handler()))
	e.GET("/private", func(c echo.Context) error {
		user, ok := signet.UserFromContext(c.Request().Context())
		if !ok {
			return c.String(http.StatusUnauthorized, "unauthorized")
		}
		return c.String(http.StatusOK, "hello "+user.Email)
	}, echo.WrapMiddleware(auth.RequireAuth))
	server := &http.Server{
		Addr:              ":8080",
		Handler:           e,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("listening on http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}
