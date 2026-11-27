// Command ss5web logs in to the shopsocks5.com website and prints one page
// of the sock list (exit IP, location, ISP, risk) without taking any sock.
//
// The account comes from the environment so it never lands in shell
// history: SS5_WEB_USER (user name or email) and SS5_WEB_PASS.
//
//	ss5web -country US -type residential -level 1 -page 1
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-dispatcher/internal/shopsocks5"
)

func main() {
	f := shopsocks5.WebFilter{}
	flag.StringVar(&f.Country, "country", "", "2-letter country code, e.g. US")
	flag.StringVar(&f.State, "state", "", "state name")
	flag.StringVar(&f.City, "city", "", "city name")
	flag.StringVar(&f.Zipcode, "zip", "", "zipcode")
	flag.StringVar(&f.ISP, "isp", "", "ISP name")
	flag.StringVar(&f.SockType, "type", "", "residential, business, cellular or hosting")
	flag.StringVar(&f.Level, "level", "", "risk level 1-4 (1 = Low)")
	flag.IntVar(&f.Page, "page", 1, "page number")
	flag.Parse()

	user, pass := os.Getenv("SS5_WEB_USER"), os.Getenv("SS5_WEB_PASS")
	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "set SS5_WEB_USER and SS5_WEB_PASS")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c := shopsocks5.NewWeb("")
	if err := c.Login(ctx, user, pass); err != nil {
		fail(err)
	}
	p, err := c.Profile(ctx)
	if err != nil {
		fail(err)
	}
	fmt.Printf("account %s | plan %s | used today %d/%d | expires %s | captcha passed: %v\n",
		p.UserName, p.PlanName, p.UsedToday, p.DailyLimit, p.Expired, p.CaptchaPassed)

	page, err := c.List(ctx, f)
	if err != nil {
		fail(err)
	}
	fmt.Printf("%d socks match, page %d (%d per page)\n", page.Total, page.Page, page.PageSize)
	for _, s := range page.Socks {
		fmt.Printf("%-15s %-2s %-18s %-20s %-7s %-11s score %-3d level %d  %s\n",
			s.IPReal, s.Country, s.State, s.City, s.Zipcode, s.SockType, s.Score, s.Level, s.ISP)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	if errors.Is(err, shopsocks5.ErrWebCaptcha) {
		os.Exit(3)
	}
	os.Exit(1)
}
