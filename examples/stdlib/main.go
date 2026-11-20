// Command stdlib demonstrates Signet with the standard library router.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

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

func main() {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "signet.db")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := sqlite.New(db)
	if err := store.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	cfg := signet.DefaultConfig()
	cfg.Store = store
	cfg.Mailer = console.New(os.Stdout) // development only: prints links
	cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
	cfg.CSRFKey = key
	cfg.AppURL = "http://localhost:8080"
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
