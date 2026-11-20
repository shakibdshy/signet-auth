package signet_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func ExampleClient_SignUp() {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	result, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
		Name:     "Ada",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.User.Email)
	// Output: user@example.com
}

func ExampleClient_SignIn() {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	_, err = client.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.User.Email, result.SessionToken != "")
	// Output: user@example.com true
}

func ExampleClient_ListSessions() {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	user, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	}); err != nil {
		panic(err)
	}
	sessions, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: user.User.ID})
	if err != nil {
		panic(err)
	}
	fmt.Println(len(sessions.Sessions))
	// Output: 1
}

func ExampleClient_ExchangeToken() {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("an-example-key-at-least-32-bytes-long")}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	_, err = client.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	pair, err := client.ExchangeToken(context.Background(), signet.TokenInput{
		Email: "user@example.com", Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(pair.AccessToken != "", pair.RefreshToken != "")
	// Output: true true
}

func exampleToken(msg signet.Message) string {
	for _, line := range strings.Split(msg.TextBody, "\n") {
		if strings.HasPrefix(line, "https://") {
			parsed, err := url.Parse(line)
			if err == nil {
				return parsed.Query().Get("token")
			}
		}
	}
	return ""
}

func ExampleClient_VerifyEmail() {
	cfg := signet.DefaultConfig()
	cfg.CSRFKey = make([]byte, 32)
	cfg.Store = testutil.NewStore()
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	_, err = client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse battery staple",
	})
	if err != nil {
		panic(err)
	}
	mailer := cfg.Mailer.(*testutil.Mailer)
	token := exampleToken(mailer.Messages[0])
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: token}); err != nil {
		panic(err)
	}
	_, err = client.SignIn(context.Background(), signet.SignInInput{
		Email: "user@example.com", Password: "correct horse battery staple",
	})
	fmt.Println(err == nil)
	// Output: true
}

func ExampleClient_ResetPassword() {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "old-password",
	}); err != nil {
		panic(err)
	}
	if err := client.SendPasswordReset(context.Background(), signet.SendPasswordResetInput{
		Email: "user@example.com",
	}); err != nil {
		panic(err)
	}
	mailer := cfg.Mailer.(*testutil.Mailer)
	token := exampleToken(mailer.Messages[len(mailer.Messages)-1])
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{
		Token: token, NewPassword: "new-password",
	}); err != nil {
		panic(err)
	}
	_, err = client.SignIn(context.Background(), signet.SignInInput{
		Email: "user@example.com", Password: "new-password",
	})
	fmt.Println(err == nil)
	// Output: true
}

func exampleState(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("state")
}

func ExampleClient_OAuthStart() {
	cfg := signet.DefaultConfig()
	cfg.CSRFKey = make([]byte, 32)
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "google", Redirect: "https://app.example.com/dashboard",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.Contains(result.URL, "code_challenge="))
	// Output: true
}

func ExampleClient_OAuthCallback() {
	cfg := signet.DefaultConfig()
	cfg.CSRFKey = make([]byte, 32)
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	started, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "google", Redirect: "https://app.example.com/dashboard",
	})
	if err != nil {
		panic(err)
	}
	result, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{
		Code: "authorization-code", State: exampleState(started.URL),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.User.Email, result.User.EmailVerified)
	// Output: user@example.com true
}
