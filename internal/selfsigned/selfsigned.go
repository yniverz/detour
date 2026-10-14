// Package selfsigned generates an in-memory self-signed TLS certificate, so the
// proxy listener can be encrypted without managing certificate files.
package selfsigned

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Validity of generated certificates. Clients of a self-signed certificate skip
// verification or pin it, so a long lifetime avoids surprise expiry; a new
// certificate is generated on every start anyway.
const Validity = 10 * 365 * 24 * time.Hour

// Generate creates a certificate for the given hosts (DNS names and/or IPs).
func Generate(hosts []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	cn := "detour"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"detour self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// DefaultHosts returns the machine hostname, localhost and all local unicast IPs.
func DefaultHosts() []string {
	var hosts []string
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, "localhost")
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() && !ipn.IP.IsMulticast() {
			hosts = append(hosts, ipn.IP.String())
		}
	}
	return hosts
}

// Fingerprint returns the SHA-256 fingerprint of the certificate (colon separated hex).
func Fingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// Describe returns a short description of the names in the certificate.
func Describe(c tls.Certificate) string {
	if c.Leaf == nil {
		return ""
	}
	names := append([]string{}, c.Leaf.DNSNames...)
	for _, ip := range c.Leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return fmt.Sprintf("%s (valid until %s)", strings.Join(names, ", "), c.Leaf.NotAfter.Format("2006-01-02"))
}
