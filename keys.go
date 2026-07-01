package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

type signerConfig struct {
	PrivateKey   crypto.Signer
	Certificates []*x509.Certificate
}

type loadSignerOptions struct {
	keyPath  string
	certPath string
	keyPass  string
	p12Path  string
	p12Pass  string
}

type certificate struct {
	Raw []byte
}

func loadSigner(opts loadSignerOptions) (signerConfig, error) {
	if opts.p12Path != "" {
		if opts.keyPath != "" || opts.certPath != "" {
			return signerConfig{}, errors.New("--p12 cannot be combined with --key or --cert")
		}
		return loadPKCS12Signer(opts.p12Path, opts.p12Pass)
	}
	if opts.keyPath == "" || opts.certPath == "" {
		return signerConfig{}, errors.New("either --p12 or both --key and --cert are required")
	}

	privateKey, err := loadPrivateKey(opts.keyPath, opts.keyPass)
	if err != nil {
		return signerConfig{}, err
	}
	certs, err := loadCertificates(opts.certPath)
	if err != nil {
		return signerConfig{}, err
	}
	if len(certs) == 0 {
		return signerConfig{}, errors.New("no certificates found")
	}
	if err := validateSigner(privateKey, certs[0]); err != nil {
		return signerConfig{}, err
	}
	return signerConfig{PrivateKey: privateKey, Certificates: certs}, nil
}

func loadPKCS12Signer(path string, password string) (signerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return signerConfig{}, fmt.Errorf("read PKCS#12 signer: %w", err)
	}
	privateKeyAny, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return signerConfig{}, fmt.Errorf("decode PKCS#12 signer: %w", err)
	}
	privateKey, ok := privateKeyAny.(crypto.Signer)
	if !ok {
		return signerConfig{}, fmt.Errorf("PKCS#12 private key is not a supported signer: %T", privateKeyAny)
	}
	certs := append([]*x509.Certificate{cert}, caCerts...)
	if err := validateSigner(privateKey, cert); err != nil {
		return signerConfig{}, err
	}
	return signerConfig{PrivateKey: privateKey, Certificates: certs}, nil
}

func loadPrivateKey(path string, password string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if !stringsHasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		der := block.Bytes
		if x509.IsEncryptedPEMBlock(block) {
			if password == "" {
				return nil, errors.New("private key is encrypted; provide --key-pass")
			}
			decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, fmt.Errorf("decrypt private key: %w", err)
			}
			der = decrypted
		}
		return parsePrivateKeyDER(der)
	}

	return parsePrivateKeyDER(data)
}

func parsePrivateKeyDER(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key as PKCS#8, PKCS#1 RSA, or SEC1 EC")
}

func loadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	var certs []*x509.Certificate
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

func validateSigner(privateKey crypto.Signer, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("leaf certificate is missing")
	}
	if err := validateSupportedPrivateKey(privateKey); err != nil {
		return err
	}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("leaf certificate does not contain an RSA public key")
		}
		if key.PublicKey.E != pub.E || key.PublicKey.N.Cmp(pub.N) != 0 {
			return errors.New("private key does not match leaf certificate public key")
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("leaf certificate does not contain an ECDSA public key")
		}
		if key.Curve != pub.Curve || key.X.Cmp(pub.X) != 0 || key.Y.Cmp(pub.Y) != 0 {
			return errors.New("private key does not match leaf certificate public key")
		}
	default:
		return fmt.Errorf("unsupported private key type %T", privateKey)
	}
	return nil
}

func validateSupportedPrivateKey(privateKey crypto.Signer) error {
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return nil
	default:
		return fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func publicKeyMatchesCertificate(publicKeyDER []byte, cert *x509.Certificate) bool {
	if bytes.Equal(publicKeyDER, cert.RawSubjectPublicKeyInfo) {
		return true
	}
	marshaled, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(publicKeyDER, marshaled)
}

func stringsHasSuffix(s string, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
