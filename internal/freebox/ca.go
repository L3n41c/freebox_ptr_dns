// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	_ "embed"
	"crypto/x509"
)

//go:embed ca.pem
var caPem []byte

// certPool contains the Freebox Root CA and Freebox ECC Root CA
// certificates used to validate Freebox HTTPS certificates.
var certPool *x509.CertPool

func init() {
	certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPem) {
		panic("failed to load embedded CA certificates")
	}
}
