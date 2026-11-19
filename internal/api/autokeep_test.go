package api

import (
	"fmt"
	"testing"

	"proxy-dispatcher/internal/config"
)

func TestAKPositions(t *testing.T) {
	m := config.PortMapping{PortStart: 40000, PortEnd: 40009}
	cases := []struct {
		ak   config.AutoKeepConfig
		want string
	}{
		{config.AutoKeepConfig{Target: 3}, "[0 1 2]"},
		{config.AutoKeepConfig{Target: 50}, "[0 1 2 3 4 5 6 7 8 9]"},
		{config.AutoKeepConfig{Target: 3, Ports: "40005-40007,40002"}, "[2 5 6 7]"},
		{config.AutoKeepConfig{Ports: "40008-40020,40008"}, "[8 9]"},
		{config.AutoKeepConfig{Target: 3, Ports: "abc"}, "[]"},
	}
	for _, c := range cases {
		if got := fmt.Sprint(akPositions(c.ak, m)); got != c.want {
			t.Errorf("akPositions(%+v) = %s, want %s", c.ak, got, c.want)
		}
	}
}
