package proxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type authenticator struct {
	enabled      bool
	username     string
	password     string
	expectedHTTP []byte
}

func newAuthenticator(username, password string) *authenticator {
	var expectedHTTP []byte
	// SOCKS5 credentials are byte strings. HTTP Basic advertises UTF-8.
	if utf8.ValidString(username) && utf8.ValidString(password) {
		expectedHTTP = canonicalBasicCredential([]byte(username + ":" + password))
	}
	return &authenticator{
		enabled:      username != "",
		username:     username,
		password:     password,
		expectedHTTP: expectedHTTP,
	}
}

func (a *authenticator) checkHTTP(r *http.Request) bool {
	if !a.enabled {
		return true
	}
	if a.expectedHTTP == nil {
		return false
	}

	const prefix = "Basic "
	header := r.Header.Get("Proxy-Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	// Each input rune has at most four UTF-8 bytes and contributes at
	// least one byte to the canonical decomposition.
	if len(token) > base64.StdEncoding.EncodedLen(4*len(a.expectedHTTP)) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil || !utf8.Valid(decoded) {
		return false
	}
	return subtle.ConstantTimeCompare(canonicalBasicCredential(decoded), a.expectedHTTP) == 1
}

// Equal canonical decompositions are equivalent under NFC. x/text's
// whole-string forms can insert U+034F in long nonstarter runs, so only
// use that result when it has preserved the number of literal joiners.
func canonicalBasicCredential(input []byte) []byte {
	decomposed := norm.NFD.Bytes(input)
	joiner := []byte(norm.GraphemeJoiner)
	if bytes.Count(decomposed, joiner) == bytes.Count(input, joiner) {
		return decomposed
	}

	type mark struct {
		text  []byte
		class uint8
	}
	result := make([]byte, 0, len(decomposed))
	var marks []mark
	flushMarks := func() {
		slices.SortStableFunc(marks, func(a, b mark) int { return int(a.class) - int(b.class) })
		for _, mark := range marks {
			result = append(result, mark.text...)
		}
		marks = marks[:0]
	}
	// Decompose each rune independently, then order each run of
	// nonstarters without imposing a stream-safe boundary.
	for len(input) > 0 {
		_, size := utf8.DecodeRune(input)
		for part := norm.NFD.Bytes(input[:size]); len(part) > 0; {
			_, width := utf8.DecodeRune(part)
			runeBytes := part[:width]
			if class := norm.NFD.Properties(runeBytes).CCC(); class == 0 {
				flushMarks()
				result = append(result, runeBytes...)
			} else {
				marks = append(marks, mark{text: runeBytes, class: class})
			}
			part = part[width:]
		}
		input = input[size:]
	}
	flushMarks()
	return result
}

func (a *authenticator) checkSOCKS5(username, password []byte) bool {
	userOK := subtle.ConstantTimeCompare(username, []byte(a.username)) == 1
	passOK := subtle.ConstantTimeCompare(password, []byte(a.password)) == 1
	return userOK && passOK
}
