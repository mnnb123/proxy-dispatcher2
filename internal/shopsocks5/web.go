package shopsocks5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WebClient reads the sock list of the shopsocks5.com website, which the
// public API does not expose: every sock with its exit IP, location, ISP
// and risk score before it is taken.
//
// It is read-only. It logs in the way the site's own pages do and never
// takes, views or renews a sock: taking a sock stays with Client (the
// official API), for example GetSocks with the ip_real filter.
//
// The site protects these pages with a slider captcha. This client does not
// solve it: when the site asks for one, calls fail with ErrWebCaptcha and
// the captcha has to be passed once in a real browser.
type WebClient struct {
	BaseURL string
	HTTP    *http.Client

	token string
}

var (
	// ErrWebCaptcha means the site wants its slider captcha solved.
	ErrWebCaptcha = errors.New("shopsocks5 web: the site asks for a captcha; open it in a browser and pass it once")
	// ErrWeb2FA means the account has two-factor login enabled.
	ErrWeb2FA = errors.New("shopsocks5 web: the account needs a 2FA code")
	// ErrWebBlocked means the site reports the account as locked.
	ErrWebBlocked = errors.New("shopsocks5 web: the account is locked by the site")
	// ErrWebNotLoggedIn means there is no session token yet, or the site no
	// longer accepts it.
	ErrWebNotLoggedIn = errors.New("shopsocks5 web: not logged in")
)

// NewWeb returns a website client; an empty baseURL selects DefaultBaseURL.
func NewWeb(baseURL string) *WebClient {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &WebClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 40 * time.Second},
	}
}

// Token returns the session token of the current login ("" before Login).
func (c *WebClient) Token() string { return c.token }

// SetToken reuses a session token from an earlier Login.
func (c *WebClient) SetToken(token string) { c.token = strings.TrimSpace(token) }

// webStatus is the envelope every website reply shares.
type webStatus struct {
	Status   string      `json:"status"`
	Message  string      `json:"message"`
	Subtitle string      `json:"subtitle"`
	IsBlock  interface{} `json:"is_block"`
}

func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != "" && t != "0" && t != "false"
	}
	return false
}

// do sends one request and decodes the reply into out. The site answers
// errors as HTTP 200 with status != "success". Error texts never include
// the request, so the password and token cannot leak through them.
func (c *WebClient) do(ctx context.Context, method, path string, query url.Values, body map[string]interface{}, out interface{}) error {
	u := c.BaseURL + path
	if query != nil {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("shopsocks5 web: bad request")
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("shopsocks5 web: bad request")
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if body != nil {
		// The site's pages post a JSON document under this content type.
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL: it carries the session token
		}
		return fmt.Errorf("shopsocks5 web: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("shopsocks5 web: read reply: %w", err)
	}
	var st webStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		// Not JSON: a Cloudflare challenge or an error page.
		return fmt.Errorf("shopsocks5 web: unexpected reply (HTTP %d)", resp.StatusCode)
	}
	if st.Status != "success" {
		if truthy(st.IsBlock) {
			return ErrWebBlocked
		}
		msg := st.Message
		if msg == "" {
			msg = st.Subtitle
		}
		if msg == "" {
			msg = "request rejected"
		}
		return fmt.Errorf("shopsocks5 web: %s", msg)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("shopsocks5 web: unexpected reply format")
		}
	}
	return nil
}

func (c *WebClient) authQuery(q url.Values) (url.Values, error) {
	if c.token == "" {
		return nil, ErrWebNotLoggedIn
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("_token", "")
	q.Set("authorization", c.token)
	return q, nil
}

// Login signs in with the website account (user name or email, and the
// website password, not the API token) and keeps the session token.
func (c *WebClient) Login(ctx context.Context, user, password string) error {
	var out struct {
		Response struct {
			Token string `json:"token"`
		} `json:"response"`
	}
	err := c.do(ctx, http.MethodPost, "/account/login", nil,
		map[string]interface{}{"username": user, "password": password, "_token": "", "authorization": nil}, &out)
	if err != nil {
		return err
	}
	if out.Response.Token == "" {
		return fmt.Errorf("shopsocks5 web: login reply has no session token")
	}
	c.token = out.Response.Token
	// An account with 2FA gets a token that is not usable until the code is
	// entered; the site's pages run the same check after login.
	if err := c.do(ctx, http.MethodPost, "/authenticator/checkVerify2faFrontend", nil,
		map[string]interface{}{"one_time_password": nil, "_token": "", "authorization": c.token}, nil); err != nil {
		c.token = ""
		if errors.Is(err, ErrWebBlocked) {
			return err
		}
		// Keep what the site said: the same check also fails for reasons
		// other than a pending 2FA code.
		return fmt.Errorf("%w (trang tra loi: %s)", ErrWeb2FA, strings.TrimPrefix(err.Error(), "shopsocks5 web: "))
	}
	return nil
}

// WebProfile is the part of the account page this client uses.
type WebProfile struct {
	UserName      string `json:"user_name"`
	PlanName      string `json:"plan_current_name"`
	DailyLimit    int    `json:"plan_daily_limit"`
	UsedToday     int    `json:"count"`
	Expired       string `json:"user_exdate"`
	CaptchaPassed bool   `json:"is_verify_captcha"`
}

// Profile reads the plan, today's usage and whether the captcha is passed.
func (c *WebClient) Profile(ctx context.Context) (*WebProfile, error) {
	q, err := c.authQuery(nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Response WebProfile `json:"response"`
	}
	if err := c.do(ctx, http.MethodGet, "/profile/index", q, nil, &out); err != nil {
		return nil, err
	}
	return &out.Response, nil
}

// WebFilter narrows the list. Empty fields mean "all".
type WebFilter struct {
	Country  string // 2-letter code, e.g. US
	State    string
	City     string
	Zipcode  string
	ISP      string
	SockType string // residential, business, cellular, hosting
	Level    string // risk level 1-4 (1 = Low)
	Page     int    // 1-based; 0 means 1
	PageSize int    // 0 means 20, the size the site uses
}

// WebSock is one row of the website's list. Taking it is a separate step.
type WebSock struct {
	ID        int64  `json:"sock_id"`
	IPReal    string `json:"ip_real"` // exit IP
	ISP       string `json:"sock_hostname"`
	Zipcode   string `json:"sock_zip"`
	City      string `json:"sock_city"`
	State     string `json:"sock_states"`
	Country   string `json:"sock_country"`
	SockType  string `json:"type_sock"`
	Score     int    `json:"score"` // risk score 0-100, lower is cleaner
	Level     int    `json:"level"` // 1 Low .. 4 Very High
	VPN       int    `json:"vpn"`
	BlackList int    `json:"sock_back_list"` // 1 = on a spam blacklist
	Online    string `json:"sock_times"`
}

// WebPage is one page of the list.
type WebPage struct {
	Socks     []WebSock `json:"response"`
	Total     int       `json:"total"`
	Page      int       `json:"current"`
	PageSize  int       `json:"limit"`
	UsedToday int       `json:"used_today"`
}

// List reads one page of available socks. It costs no quota. It fails with
// ErrWebCaptcha, before asking for the list, when the site wants a captcha.
func (c *WebClient) List(ctx context.Context, f WebFilter) (*WebPage, error) {
	p, err := c.Profile(ctx)
	if err != nil {
		return nil, err
	}
	if !p.CaptchaPassed {
		return nil, ErrWebCaptcha
	}
	q := url.Values{"all": {"1"}}
	set := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			q.Set(k, v)
		}
	}
	set("sock_country", strings.ToUpper(f.Country))
	set("sock_state", f.State)
	set("sock_city", f.City)
	set("sock_zipcode", f.Zipcode)
	set("sock_hostname", f.ISP)
	set("type_sock", strings.ToLower(f.SockType))
	set("level", f.Level)
	page, size := max(f.Page, 1), f.PageSize
	if size <= 0 {
		size = 20
	}
	q.Set("current", strconv.Itoa(page))
	q.Set("pageSize", strconv.Itoa(size))
	if q, err = c.authQuery(q); err != nil {
		return nil, err
	}
	var out WebPage
	if err := c.do(ctx, http.MethodGet, "/sock_list", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
