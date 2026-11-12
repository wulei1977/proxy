package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

func loadTLSConfig(certFile, keyFile, listenAddr string) (*tls.Config, string, bool, error) {
	var (
		cert      tls.Certificate
		generated bool
		err       error
	)

	if certFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, "", false, fmt.Errorf("load TLS certificate: %w", err)
		}
	} else {
		cert, err = generateSelfSignedCertificate(listenAddr)
		if err != nil {
			return nil, "", false, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		generated = true
	}
	if len(cert.Certificate) == 0 {
		return nil, "", false, fmt.Errorf("TLS certificate contains no certificates")
	}

	fingerprint := certificateFingerprint(cert.Certificate[0])
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	return config, fingerprint, generated, nil
}

func generateSelfSignedCertificate(listenAddr string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if host, _, err := net.SplitHostPort(listenAddr); err == nil && host != "" {
		switch host {
		case "0.0.0.0", "::":
		default:
			if ip := net.ParseIP(host); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			} else if host != "localhost" {
				dnsNames = append(dnsNames, host)
			}
		}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "goproxy",
			Organization: []string{"goproxy"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func certificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}
