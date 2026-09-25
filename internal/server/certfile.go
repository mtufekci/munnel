package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// certCheckInterval bounds how often CertFile stats the files. Checks happen
// only during TLS handshakes (one per client connect), so this is cheap.
const certCheckInterval = 10 * time.Second

// CertFile serves the certificate for the TLS control listener from a
// PEM certificate + key pair on disk and reloads it when either file changes.
// That lets the server reuse the certificate Caddy (or certbot) keeps renewed
// for the apex domain without a restart. Use GetCertificate in a tls.Config.
//
// A pair that cannot be loaded does not stop the server: handshakes fail
// with the load error and every later handshake retries, so the listener
// recovers by itself once the files appear (Caddy may obtain the certificate
// after munnel-server has started).
type CertFile struct {
	certPath, keyPath string

	mu       sync.Mutex
	cert     *tls.Certificate
	stamp    string    // mtime+size of both files at the last load attempt
	checked  time.Time // last stat
	lastErr  error
	interval time.Duration
}

// NewCertFile builds a CertFile and tries a first load; the error (if any) is
// informational, since GetCertificate keeps retrying.
func NewCertFile(certPath, keyPath string) (*CertFile, error) {
	c := &CertFile{certPath: certPath, keyPath: keyPath, interval: certCheckInterval}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c, c.refreshLocked(true)
}

// GetCertificate implements tls.Config.GetCertificate.
func (c *CertFile) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert == nil || time.Since(c.checked) >= c.interval {
		_ = c.refreshLocked(false)
	}
	if c.cert == nil {
		return nil, fmt.Errorf("no control TLS certificate: %w", c.lastErr)
	}
	return c.cert, nil
}

// refreshLocked reloads the pair if the files changed since the last attempt
// (or always, with force). A failed reload keeps serving the previous
// certificate: a renewal caught half-written must not take the port down.
func (c *CertFile) refreshLocked(force bool) error {
	c.checked = time.Now()
	stamp, err := fileStamp(c.certPath, c.keyPath)
	if err != nil {
		c.lastErr = err
		return err
	}
	if !force && stamp == c.stamp && c.cert != nil {
		return nil
	}
	c.stamp = stamp
	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		c.lastErr = err
		return err
	}
	c.cert, c.lastErr = &cert, nil
	return nil
}

func fileStamp(paths ...string) (string, error) {
	stamp := ""
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if fi.IsDir() {
			return "", errors.New(p + " is a directory")
		}
		stamp += fmt.Sprintf("%d/%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	return stamp, nil
}
