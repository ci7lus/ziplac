package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
)

type signResult struct {
	RemovedExistingSigningBlock bool
}

func signZipV2(input []byte, signer signerConfig, alg signatureAlgorithm) ([]byte, signResult, error) {
	if len(signer.Certificates) == 0 {
		return nil, signResult{}, errors.New("no signer certificates configured")
	}
	if err := validateSigner(signer.PrivateKey, signer.Certificates[0]); err != nil {
		return nil, signResult{}, err
	}
	if err := ensureAlgorithmMatchesKey(alg, signer.PrivateKey); err != nil {
		return nil, signResult{}, err
	}

	info, err := inspectZip(input)
	if err != nil {
		return nil, signResult{}, err
	}
	signingBlock, hasSigningBlock, err := findSigningBlock(input, info.CentralDirOffset)
	if err != nil {
		return nil, signResult{}, err
	}

	beforeEnd := info.CentralDirOffset
	if hasSigningBlock {
		beforeEnd = signingBlock.Offset
	}
	before := input[:beforeEnd]
	centralDir := input[info.CentralDirOffset:info.EOCDOffset]
	eocdForDigest := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(eocdForDigest, uint64(len(before))); err != nil {
		return nil, signResult{}, err
	}

	contentDigest, err := computeContentDigest(alg.ContentDigest, before, centralDir, eocdForDigest)
	if err != nil {
		return nil, signResult{}, err
	}

	v2Block, err := buildV2SignatureBlock(signer, alg, contentDigest)
	if err != nil {
		return nil, signResult{}, err
	}
	newSigningBlock := buildSigningBlock(v2Block)

	finalCentralDirOffset := uint64(len(before) + len(newSigningBlock))
	if finalCentralDirOffset > math.MaxUint32 {
		return nil, signResult{}, fmt.Errorf("central directory offset after signing exceeds ZIP32 limit: %d", finalCentralDirOffset)
	}
	finalEOCD := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(finalEOCD, finalCentralDirOffset); err != nil {
		return nil, signResult{}, err
	}

	out := make([]byte, 0, len(before)+len(newSigningBlock)+len(centralDir)+len(finalEOCD))
	out = append(out, before...)
	out = append(out, newSigningBlock...)
	out = append(out, centralDir...)
	out = append(out, finalEOCD...)

	return out, signResult{RemovedExistingSigningBlock: hasSigningBlock}, nil
}

func buildV2SignatureBlock(signer signerConfig, alg signatureAlgorithm, contentDigest []byte) ([]byte, error) {
	signedData, err := buildSignedData(signer.Certificates, alg, contentDigest)
	if err != nil {
		return nil, err
	}
	signature, err := signSignedData(signer, alg, signedData)
	if err != nil {
		return nil, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(signer.Certificates[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode signer public key: %w", err)
	}

	signatures := encodeIntBytesPairs([]intBytesPair{{ID: alg.ID, Value: signature}})
	signerBlock := encodeSequence([][]byte{signedData, signatures, publicKeyDER})
	signers := encodeSequence([][]byte{signerBlock})
	return encodeSequence([][]byte{signers}), nil
}

func buildSignedData(certs []*x509.Certificate, alg signatureAlgorithm, contentDigest []byte) ([]byte, error) {
	certBytes := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, errors.New("certificate chain contains an empty certificate")
		}
		certBytes = append(certBytes, cert.Raw)
	}

	digests := encodeIntBytesPairs([]intBytesPair{{ID: alg.ID, Value: contentDigest}})
	certificates := encodeSequence(certBytes)
	additionalAttributes := []byte{}
	return encodeSequence([][]byte{digests, certificates, additionalAttributes}), nil
}

func signSignedData(signer signerConfig, alg signatureAlgorithm, signedData []byte) ([]byte, error) {
	if !alg.Hash.Available() {
		return nil, fmt.Errorf("hash %s is not available", alg.Hash.String())
	}
	h := alg.Hash.New()
	_, _ = h.Write(signedData)
	digest := h.Sum(nil)

	switch alg.Kind {
	case signatureKindRSAPKCS1:
		key := signer.PrivateKey.(*rsa.PrivateKey)
		return rsa.SignPKCS1v15(rand.Reader, key, alg.Hash, digest)
	case signatureKindRSAPSS:
		key := signer.PrivateKey.(*rsa.PrivateKey)
		return rsa.SignPSS(rand.Reader, key, alg.Hash, digest, &rsa.PSSOptions{
			SaltLength: alg.PSSSaltLength,
			Hash:       alg.Hash,
		})
	case signatureKindECDSA:
		return signer.PrivateKey.Sign(rand.Reader, digest, alg.Hash)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm %s", alg.Name)
	}
}

func stripSigningBlockForTest(input []byte) ([]byte, bool, error) {
	info, err := inspectZip(input)
	if err != nil {
		return nil, false, err
	}
	signingBlock, ok, err := findSigningBlock(input, info.CentralDirOffset)
	if err != nil || !ok {
		return input, ok, err
	}
	eocd := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(eocd, signingBlock.Offset); err != nil {
		return nil, false, err
	}
	out := bytes.Join([][]byte{
		input[:signingBlock.Offset],
		input[info.CentralDirOffset:info.EOCDOffset],
		eocd,
	}, nil)
	return out, true, nil
}
