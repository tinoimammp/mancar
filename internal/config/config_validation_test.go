package config_test

import (
	"strings"
	"testing"
)

func TestLoad_LogLevel(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error", "WARN"} {
		if _, err := loadWith(prodEnv().with("LOG_LEVEL", lvl)); err != nil {
			t.Errorf("LOG_LEVEL=%s rejected: %v", lvl, err)
		}
	}
	for _, lvl := range []string{"verbose", "trace", "warning", "0"} {
		if ce := loadErr(t, prodEnv().with("LOG_LEVEL", lvl)); !hasProblem(ce, "LOG_LEVEL") {
			t.Errorf("LOG_LEVEL=%s accepted: %v", lvl, ce.Problems)
		}
	}
}

func TestLoad_ListenAddr(t *testing.T) {
	for _, a := range []string{":8080", "0.0.0.0:80", "127.0.0.1:9000", "[::1]:8080"} {
		if _, err := loadWith(prodEnv().with("LISTEN_ADDR", a)); err != nil {
			t.Errorf("LISTEN_ADDR=%s rejected: %v", a, err)
		}
	}
	for _, a := range []string{"8080", "localhost", "http://0.0.0.0:80", "::1:80x"} {
		if ce := loadErr(t, prodEnv().with("LISTEN_ADDR", a)); !hasProblem(ce, "LISTEN_ADDR") {
			t.Errorf("LISTEN_ADDR=%s accepted: %v", a, ce.Problems)
		}
	}
}

func TestLoad_PublicPort(t *testing.T) {
	for _, p := range []string{"", "1", "443", "8443", "65535"} {
		if _, err := loadWith(prodEnv().with("PUBLIC_PORT", p)); err != nil {
			t.Errorf("PUBLIC_PORT=%q rejected: %v", p, err)
		}
	}
	for _, p := range []string{"0", "65536", "-1", "https", "80 80"} {
		if ce := loadErr(t, prodEnv().with("PUBLIC_PORT", p)); !hasProblem(ce, "PUBLIC_PORT") {
			t.Errorf("PUBLIC_PORT=%q accepted: %v", p, ce.Problems)
		}
	}
}

func TestLoad_DevAgentTokenMustBeWellFormed(t *testing.T) {
	good := "mc_" + strings.Repeat("a", 64)
	if _, err := loadWith(devEnv().with("DEV_AGENT_TOKEN", good)); err != nil {
		t.Errorf("valid dev token rejected: %v", err)
	}
	for _, tok := range []string{"dev-token", "mc_short", good + "x", strings.Repeat("a", 67)} {
		// The gateway drops malformed tokens before authenticating, so a
		// bad DEV_AGENT_TOKEN would silently never work: fail at start-up.
		if ce := loadErr(t, devEnv().with("DEV_AGENT_TOKEN", tok)); !hasProblem(ce, "DEV_AGENT_TOKEN") {
			t.Errorf("DEV_AGENT_TOKEN=%q accepted: %v", tok, ce.Problems)
		}
	}
}

func TestLoad_AuthFailureLimit(t *testing.T) {
	if c := mustLoad(t, prodEnv()); c.AuthFailureLimit != 10 {
		t.Errorf("default = %d, want 10", c.AuthFailureLimit)
	}
	for in, want := range map[string]int{"0": 0, "5": 5, "100": 100} {
		if c := mustLoad(t, prodEnv().with("AUTH_FAILURE_LIMIT_PER_MINUTE", in)); c.AuthFailureLimit != want {
			t.Errorf("AUTH_FAILURE_LIMIT_PER_MINUTE=%s -> %d", in, c.AuthFailureLimit)
		}
	}
	for _, bad := range []string{"-1", "many", "1.5"} {
		if ce := loadErr(t, prodEnv().with("AUTH_FAILURE_LIMIT_PER_MINUTE", bad)); !hasProblem(ce, "AUTH_FAILURE_LIMIT_PER_MINUTE") {
			t.Errorf("%q accepted: %v", bad, ce.Problems)
		}
	}
}
