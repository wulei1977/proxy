package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func readDotEnv(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !envKey.MatchString(key) {
			return nil, fmt.Errorf("%s 第 %d 行需要使用 KEY=VALUE 格式", path, lineNumber)
		}
		value, ok := parseDotEnvValue(strings.TrimSpace(raw))
		if !ok {
			return nil, fmt.Errorf("%s 第 %d 行的引号或行尾注释格式无效", path, lineNumber)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s 第 %d 行: %w", path, lineNumber+1, err)
	}
	return values, nil
}

func parseDotEnvValue(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	if raw[0] == '\'' || raw[0] == '"' {
		value, rest, closed := strings.Cut(raw[1:], raw[:1])
		rest = strings.TrimSpace(rest)
		return value, closed && (rest == "" || strings.HasPrefix(rest, "#"))
	}
	for i := range len(raw) {
		if raw[i] == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t') {
			return strings.TrimSpace(raw[:i]), true
		}
	}
	return raw, true
}
