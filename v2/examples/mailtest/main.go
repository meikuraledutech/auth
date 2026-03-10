package main

import (
	"context"
	"fmt"
	"os"

	"github.com/meikuraledutech/mailing"
	mailingzepto "github.com/meikuraledutech/mailing/zeptomail"
)

func main() {
	apiURL := os.Getenv("ZEPTO_API_URL")
	apiKey := os.Getenv("ZEPTO_API_KEY")
	fromEmail := os.Getenv("FROM_EMAIL")

	fmt.Printf("API URL:    %s\n", apiURL)
	fmt.Printf("From Email: %s\n", fromEmail)
	fmt.Printf("API Key:    %s...\n\n", apiKey[:20])

	sender := mailingzepto.New(mailingzepto.Config{
		APIURL:   apiURL,
		Provider: "zeptomail",
	})

	status, err := sender.Send(context.Background(), mailing.Mail{
		Token:   apiKey,
		From:    fromEmail,
		To:      "dharaniadithya1998.da@gmail.com",
		Subject: "Test mail - auth v2",
		HTML:    "<p>Test email from auth v2 mailing integration.</p>",
	})

	fmt.Printf("Status: %+v\n", status)
	fmt.Printf("Error:  %v\n", err)
}
