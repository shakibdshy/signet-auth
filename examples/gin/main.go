// Command gin demonstrates Signet with the Gin framework.
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

	"github.com/gin-gonic/gin"
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
