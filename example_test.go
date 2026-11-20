package signet_test

import (
	"context"
	"fmt"

	"github.com/shakibdshy/signet"
)

func ExampleClient_SignUp() {
	cfg := signet.DefaultConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
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
	cfg := signet.DefaultConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
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
