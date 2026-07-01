package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
)

type contentDigestAlgorithm uint32

const (
	contentDigestChunkedSHA256 contentDigestAlgorithm = 1
	contentDigestChunkedSHA512 contentDigestAlgorithm = 2
)

type signatureKind int

const (
	signatureKindRSAPKCS1 signatureKind = iota
	signatureKindRSAPSS
	signatureKindECDSA
)

type signatureAlgorithm struct {
	ID            uint32
	Name          string
	Kind          signatureKind
	ContentDigest contentDigestAlgorithm
	Hash          crypto.Hash
	PSSSaltLength int
}

var signatureAlgorithms = []signatureAlgorithm{
	{
		ID:            0x0101,
		Name:          "rsa-pss-sha256",
		Kind:          signatureKindRSAPSS,
		ContentDigest: contentDigestChunkedSHA256,
		Hash:          crypto.SHA256,
		PSSSaltLength: 32,
	},
	{
		ID:            0x0102,
		Name:          "rsa-pss-sha512",
		Kind:          signatureKindRSAPSS,
		ContentDigest: contentDigestChunkedSHA512,
		Hash:          crypto.SHA512,
		PSSSaltLength: 64,
	},
	{
		ID:            0x0103,
		Name:          "rsa-pkcs1-sha256",
		Kind:          signatureKindRSAPKCS1,
		ContentDigest: contentDigestChunkedSHA256,
		Hash:          crypto.SHA256,
	},
	{
		ID:            0x0104,
		Name:          "rsa-pkcs1-sha512",
		Kind:          signatureKindRSAPKCS1,
		ContentDigest: contentDigestChunkedSHA512,
		Hash:          crypto.SHA512,
	},
	{
		ID:            0x0201,
		Name:          "ecdsa-sha256",
		Kind:          signatureKindECDSA,
		ContentDigest: contentDigestChunkedSHA256,
		Hash:          crypto.SHA256,
	},
	{
		ID:            0x0202,
		Name:          "ecdsa-sha512",
		Kind:          signatureKindECDSA,
		ContentDigest: contentDigestChunkedSHA512,
		Hash:          crypto.SHA512,
	},
}

func signatureAlgorithmByName(name string) (signatureAlgorithm, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, alg := range signatureAlgorithms {
		if alg.Name == name {
			return alg, true
		}
	}
	return signatureAlgorithm{}, false
}

func signatureAlgorithmByID(id uint32) (signatureAlgorithm, bool) {
	for _, alg := range signatureAlgorithms {
		if alg.ID == id {
			return alg, true
		}
	}
	return signatureAlgorithm{}, false
}

func selectSignatureAlgorithm(privateKey crypto.Signer, name string) (signatureAlgorithm, error) {
	if name == "" || strings.EqualFold(name, "auto") {
		switch key := privateKey.(type) {
		case *rsa.PrivateKey:
			if key.N.BitLen() <= 3072 {
				return mustSignatureAlgorithm("rsa-pkcs1-sha256"), nil
			}
			return mustSignatureAlgorithm("rsa-pkcs1-sha512"), nil
		case *ecdsa.PrivateKey:
			if key.Curve.Params().BitSize <= 256 {
				return mustSignatureAlgorithm("ecdsa-sha256"), nil
			}
			return mustSignatureAlgorithm("ecdsa-sha512"), nil
		default:
			return signatureAlgorithm{}, fmt.Errorf("unsupported private key type %T", privateKey)
		}
	}

	alg, ok := signatureAlgorithmByName(name)
	if !ok {
		return signatureAlgorithm{}, fmt.Errorf("unsupported signature algorithm %q", name)
	}
	if err := ensureAlgorithmMatchesKey(alg, privateKey); err != nil {
		return signatureAlgorithm{}, err
	}
	return alg, nil
}

func mustSignatureAlgorithm(name string) signatureAlgorithm {
	alg, ok := signatureAlgorithmByName(name)
	if !ok {
		panic("missing signature algorithm: " + name)
	}
	return alg
}

func ensureAlgorithmMatchesKey(alg signatureAlgorithm, key crypto.Signer) error {
	switch alg.Kind {
	case signatureKindRSAPKCS1, signatureKindRSAPSS:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an RSA private key", alg.Name)
		}
	case signatureKindECDSA:
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an ECDSA private key", alg.Name)
		}
	default:
		return fmt.Errorf("unsupported signature kind for %s", alg.Name)
	}
	return nil
}
