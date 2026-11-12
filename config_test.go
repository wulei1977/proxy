package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfigSources(t *testing.T) {
	t.Chdir(t.TempDir())
	writeTestDotEnv(t, "\uFEFF# proxy config\r\n"+
		"GOPROXY_USER=file-user\r\n"+
		"GOPROXY_PASS=' secret # = $ \\ ' # comment\r\n"+
		"GOPROXY_MAX_CONNECTIONS=42 # comment\r\n"+
		"GOPROXY_DIAL_TIMEOUT=2s\r\n"+
		"GOPROXY_V=true\r\n")
	env := map[string]string{
		"GOPROXY_USER":            "env-user",
		"GOPROXY_MAX_CONNECTIONS": "77",
		"GOPROXY_DIAL_TIMEOUT":    "invalid but overridden",
	}
	lookup := func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}

	cfg, err := parseConfig([]string{"-dial-timeout=3s", "-v=false"}, io.Discard, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "env-user" || cfg.Password != " secret # = $ \\ " {
		t.Fatal("credentials did not match the environment and .env sources")
	}
	if cfg.MaxConnections != 77 || cfg.DialTimeout != 3*time.Second || cfg.Verbose {
		t.Fatalf("incorrect source precedence: max=%d dial=%s verbose=%t", cfg.MaxConnections, cfg.DialTimeout, cfg.Verbose)
	}
	env["GOPROXY_USER"] = ""
	cfg, err = parseConfig([]string{"-pass=", "-dial-timeout=3s"}, io.Discard, lookup)
	if err != nil || cfg.Username != "" || cfg.Password != "" {
		t.Fatal("explicit empty values did not clear credentials", err)
	}
}

func TestConfigDiagnosticsDoNotExposeValues(t *testing.T) {
	t.Chdir(t.TempDir())
	const secret = "dummy-sensitive-value"
	lookup := func(key string) (string, bool) {
		if key == "GOPROXY_PASS" {
			return secret, true
		}
		return "", false
	}
	writeTestDotEnv(t, "GOPROXY_PASS='"+secret+"\n")
	if _, err := parseConfig(nil, io.Discard, lookup); err == nil ||
		!strings.Contains(err.Error(), "第 1 行") || strings.Contains(err.Error(), secret) {
		t.Fatalf("unexpected .env syntax error: %v", err)
	}
	writeTestDotEnv(t, "GOPROXY_MAX_CONNECTIONS="+secret+"\n")
	if _, err := parseConfig(nil, io.Discard, lookup); err == nil ||
		!strings.Contains(err.Error(), "GOPROXY_MAX_CONNECTIONS") || strings.Contains(err.Error(), secret) {
		t.Fatalf("unexpected .env value error: %v", err)
	}
	var output bytes.Buffer
	if _, err := parseConfig([]string{"-h"}, &output, lookup); !errors.Is(err, flag.ErrHelp) ||
		strings.Contains(output.String(), secret) {
		t.Fatal("help did not handle the credential environment safely")
	}
}

func writeTestDotEnv(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(".env", []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
