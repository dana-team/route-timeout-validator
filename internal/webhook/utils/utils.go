package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	certificateType = "CERTIFICATE"
	privateKeyType  = "RSA PRIVATE KEY"
)

// IsTimeoutOverMax checks if the given timeout duration is over the specified maximum duration.
// It parses the timeout string into a time.Duration and compares it with the maximum duration in seconds.
func IsTimeoutOverMax(timeout string, maxTimeoutSeconds float64) (bool, error) {
	duration, err := time.ParseDuration(timeout)
	if err != nil {
		return false, err
	}

	if duration.Seconds() > maxTimeoutSeconds {
		return true, nil
	}

	return false, nil
}

// ValidateCert checks if the given certificate is valid and correctly formatted.
func ValidateCert(cert string) (bool, error) {
	certBytes, err := decodePEMBlock(cert, certificateType)
	if err != nil {
		return false, err
	}

	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ValidateKey checks if the given key is valid and correctly formatted.
func ValidateKey(key string) (bool, error) {
	keyBytes, err := decodePEMBlock(key, privateKeyType)
	if err != nil {
		return false, err
	}
	if _, err = x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return true, nil
	}
	if _, err = x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return true, nil
	}
	if _, err = x509.ParseECPrivateKey(keyBytes); err == nil {
		return true, nil
	}
	return false, errors.New("invalid private key")
}

// decodePEMBlock decodes a PEM block and validates its type.
func decodePEMBlock(block, expectedType string) ([]byte, error) {
	decodedBlock, _ := pem.Decode([]byte(block))
	if decodedBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if decodedBlock.Type != expectedType {
		return nil, fmt.Errorf("invalid PEM block type: got %s, want %s", decodedBlock.Type, expectedType)
	}
	return decodedBlock.Bytes, nil
}
