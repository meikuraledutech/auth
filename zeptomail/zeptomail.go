package zeptomail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiURL = "https://api.zeptomail.in/v1.1/email"

// ZeptoMailer implements auth.Mailer using the ZeptoMail API.
type ZeptoMailer struct {
	apiKey    string
	fromEmail string
	client    *http.Client
}

// New creates a new ZeptoMailer.
func New(apiKey string, fromEmail string) *ZeptoMailer {
	return &ZeptoMailer{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SendOTP sends a branded OTP email to the given address.
func (m *ZeptoMailer) SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error {
	minutes := int(expiresIn.Minutes())

	body := map[string]any{
		"from": map[string]string{
			"address": m.fromEmail,
		},
		"to": []map[string]any{
			{
				"email_address": map[string]string{
					"address": email,
				},
			},
		},
		"subject":  "Your verification code",
		"htmlbody": otpEmailHTML(code, minutes),
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("auth: marshal email body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("auth: create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Zoho-enczapikey "+m.apiKey)

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth: zeptomail error (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func otpEmailHTML(code string, minutes int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="420" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
          <tr>
            <td style="background-color:#4f46e5;padding:24px;text-align:center;">
              <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:600;">Smart Forms</h1>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 32px 16px;">
              <p style="margin:0 0 8px;color:#71717a;font-size:14px;">Your verification code is</p>
              <div style="background-color:#f4f4f5;border-radius:8px;padding:16px;text-align:center;margin:16px 0;">
                <span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#18181b;">%s</span>
              </div>
              <p style="margin:16px 0 0;color:#71717a;font-size:13px;">This code expires in <strong>%d minutes</strong>. Do not share it with anyone.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px 32px;">
              <hr style="border:none;border-top:1px solid #e4e4e7;margin:0 0 16px;">
              <p style="margin:0;color:#a1a1aa;font-size:12px;text-align:center;">smart-forms.in</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`, code, minutes)
}
