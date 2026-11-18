// Package shopsocks5 is a small client for the shopsocks5.com SOCKS5 API.
package shopsocks5

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the production API host.
const DefaultBaseURL = "https://shopsocks5.com"

// Client calls the API with one account. The token travels in the request
// body, so BaseURL must be HTTPS outside tests and errors never include it.
type Client struct {
	BaseURL string
	User    string
	Token   string
	HTTP    *http.Client
}

// New returns a client; an empty baseURL selects DefaultBaseURL.
func New(baseURL, user, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		User:    user,
		Token:   token,
		HTTP:    &http.Client{Timeout: 40 * time.Second},
	}
}

// Sock is one proxy returned by /socks/all_plan.
type Sock struct {
	ID        int64  `json:"id"`
	SockIP    string `json:"sock_ip"` // gateway host:port
	User      string `json:"user_name"`
	Pass      string `json:"password"`
	IPReal    string `json:"ip_real"` // exit IP
	ISP       string `json:"isp_name"`
	City      string `json:"city"`
	State     string `json:"states"`
	Country   string `json:"country_code"`
	SockType  string `json:"sock_type"`
	SockLevel string `json:"sock_level"`
}

// Account is the /socks/myaccount reply.
type Account struct {
	UserName   string `json:"user_name"`
	PlanName   string `json:"plan_name"`
	PlanLimit  int    `json:"plan_limit"`
	Expired    string `json:"expired"`
	UsedToday  int    `json:"used_today"`
	LimitToday int    `json:"limit_today"` // remaining today
}

func (c *Client) post(ctx context.Context, path string, form url.Values, out interface{}) error {
	form.Set("user_name", c.User)
	form.Set("api_token", c.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("shopsocks5: bad request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// *url.Error carries only the URL, never the body with the token.
		return fmt.Errorf("shopsocks5: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("shopsocks5: read reply: %w", err)
	}
	// Errors come back as HTTP 200 with success=false.
	var status struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("shopsocks5: unexpected reply (HTTP %d)", resp.StatusCode)
	}
	if !status.Success {
		if status.Message == "" {
			status.Message = "request rejected"
		}
		return fmt.Errorf("shopsocks5: %s", status.Message)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("shopsocks5: unexpected reply format")
	}
	return nil
}

// GetSocks takes qty socks from the plan (each one costs quota). filters
// are optional API parameters such as country, sock_type, level, ip_real.
func (c *Client) GetSocks(ctx context.Context, qty int, filters map[string]string) ([]Sock, error) {
	form := url.Values{"qty": {strconv.Itoa(qty)}}
	for k, v := range filters {
		if v != "" {
			form.Set(k, v)
		}
	}
	var out struct {
		Response []Sock `json:"response"`
	}
	if err := c.post(ctx, "/socks/all_plan", form, &out); err != nil {
		return nil, err
	}
	return out.Response, nil
}

// Account reads plan and remaining quota. Costs nothing.
func (c *Client) Account(ctx context.Context) (*Account, error) {
	var out Account
	if err := c.post(ctx, "/socks/myaccount", url.Values{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
