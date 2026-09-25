package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a fresh self-signed certificate + key for cn and returns
// the certificate's DER bytes.
func writePair(t *testing.T, certPath, keyPath, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return der
}

func TestCertFileReloadsRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")

	// Files missing at startup (Caddy has not obtained the cert yet): not
	// fatal, handshakes fail, and the certificate is picked up once written.
	cf, err := NewCertFile(cp, kp)
	if err == nil {
		t.Fatal("want a load error for missing files")
	}
	cf.interval = 0 // check on every handshake in this test
	if _, err := cf.GetCertificate(nil); err == nil {
		t.Fatal("GetCertificate succeeded without a certificate")
	}

	first := writePair(t, cp, kp, "one.example")
	c, err := cf.GetCertificate(nil)
	if err != nil {
		t.Fatalf("certificate not picked up once present: %v", err)
	}
	if string(c.Certificate[0]) != string(first) {
		t.Fatal("served the wrong certificate")
	}

	// Renewal: new files with a later mtime replace the served certificate.
	second := writePair(t, cp, kp, "two.example")
	later := time.Now().Add(time.Minute)
	os.Chtimes(cp, later, later)
	os.Chtimes(kp, later, later)
	c, err = cf.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Certificate[0]) != string(second) {
		t.Fatal("renewed certificate not reloaded")
	}

	// A half-written renewal keeps the last good certificate in service.
	os.WriteFile(kp, []byte("garbage"), 0o600)
	evenLater := later.Add(time.Minute)
	os.Chtimes(kp, evenLater, evenLater)
	c, err = cf.GetCertificate(nil)
	if err != nil || string(c.Certificate[0]) != string(second) {
		t.Fatalf("broken renewal should keep the previous certificate, got err=%v", err)
	}
}
