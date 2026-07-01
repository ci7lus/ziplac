package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

type verifyResult struct {
	Signers []verifiedSigner
}

type verifiedSigner struct {
	Algorithms        []string
	Subject           string
	CertificateSHA256 []byte
}

type digestExpectation struct {
	Algorithm      contentDigestAlgorithm
	SignatureAlgID uint32
	Value          []byte
}

type parsedSigner struct {
	Result             verifiedSigner
	DigestExpectations []digestExpectation
	LeafCertRaw        []byte
}

func verifyZipV2(input []byte, pinnedCerts []*certificate) (verifyResult, error) {
	info, err := inspectZip(input)
	if err != nil {
		return verifyResult{}, err
	}
	signingBlock, ok, err := findSigningBlock(input, info.CentralDirOffset)
	if err != nil {
		return verifyResult{}, err
	}
	if !ok {
		return verifyResult{}, errors.New("APK Signing Block not found")
	}
	v2Block, err := findV2Block(signingBlock.Block)
	if err != nil {
		return verifyResult{}, err
	}

	parsedSigners, expectations, err := parseAndVerifyV2Signers(v2Block)
	if err != nil {
		return verifyResult{}, err
	}
	if len(parsedSigners) == 0 {
		return verifyResult{}, errors.New("v2 signature has no signers")
	}

	if err := verifyPinnedCertificate(parsedSigners, pinnedCerts); err != nil {
		return verifyResult{}, err
	}

	before := input[:signingBlock.Offset]
	centralDir := input[info.CentralDirOffset:info.EOCDOffset]
	eocd := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(eocd, signingBlock.Offset); err != nil {
		return verifyResult{}, err
	}
	if err := verifyContentDigests(expectations, before, centralDir, eocd); err != nil {
		return verifyResult{}, err
	}

	result := verifyResult{Signers: make([]verifiedSigner, 0, len(parsedSigners))}
	for _, signer := range parsedSigners {
		result.Signers = append(result.Signers, signer.Result)
	}
	return result, nil
}

func parseAndVerifyV2Signers(v2Block []byte) ([]parsedSigner, []digestExpectation, error) {
	reader := newByteReader(v2Block)
	signersBytes, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("parse v2 signers: %w", err)
	}
	if reader.hasRemaining() {
		return nil, nil, fmt.Errorf("unexpected trailing bytes after v2 signers: %d", reader.remaining())
	}

	signersReader := newByteReader(signersBytes)
	var signers []parsedSigner
	var expectations []digestExpectation
	index := 0
	for signersReader.hasRemaining() {
		index++
		signerBytes, err := signersReader.readLengthPrefixedBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("parse signer %d: %w", index, err)
		}
		signer, err := parseAndVerifySigner(signerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("signer %d: %w", index, err)
		}
		signers = append(signers, signer)
		expectations = append(expectations, signer.DigestExpectations...)
	}
	return signers, expectations, nil
}

func parseAndVerifySigner(signerBlock []byte) (parsedSigner, error) {
	reader := newByteReader(signerBlock)
	signedData, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return parsedSigner{}, fmt.Errorf("parse signed data: %w", err)
	}
	signaturesBytes, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return parsedSigner{}, fmt.Errorf("parse signatures: %w", err)
	}
	publicKeyDER, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return parsedSigner{}, fmt.Errorf("parse public key: %w", err)
	}
	if reader.hasRemaining() {
		return parsedSigner{}, fmt.Errorf("unexpected trailing bytes in signer block: %d", reader.remaining())
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return parsedSigner{}, fmt.Errorf("parse signer public key: %w", err)
	}

	signatures, err := parseIntBytesPairs(signaturesBytes)
	if err != nil {
		return parsedSigner{}, fmt.Errorf("parse signature records: %w", err)
	}
	if len(signatures) == 0 {
		return parsedSigner{}, errors.New("no signatures")
	}
	signatureAlgorithmIDs := make([]uint32, 0, len(signatures))
	seenSignatureAlgorithmIDs := make(map[uint32]struct{}, len(signatures))

	var verifiedAlgs []signatureAlgorithm
	for _, signature := range signatures {
		if _, exists := seenSignatureAlgorithmIDs[signature.ID]; exists {
			return parsedSigner{}, fmt.Errorf("duplicate signature record for signature algorithm ID 0x%04x", signature.ID)
		}
		seenSignatureAlgorithmIDs[signature.ID] = struct{}{}
		signatureAlgorithmIDs = append(signatureAlgorithmIDs, signature.ID)

		alg, ok := signatureAlgorithmByID(signature.ID)
		if !ok {
			continue
		}
		if err := verifySignedData(publicKey, alg, signedData, signature.Value); err != nil {
			return parsedSigner{}, fmt.Errorf("%s signature did not verify: %w", alg.Name, err)
		}
		verifiedAlgs = append(verifiedAlgs, alg)
	}
	if len(verifiedAlgs) == 0 {
		return parsedSigner{}, errors.New("no supported signatures")
	}

	certs, digestRecords, digestAlgorithmIDs, err := parseSignedData(signedData)
	if err != nil {
		return parsedSigner{}, err
	}
	if !sameUint32Slice(signatureAlgorithmIDs, digestAlgorithmIDs) {
		return parsedSigner{}, errors.New("signature and digest algorithm ID lists differ")
	}
	if len(certs) == 0 {
		return parsedSigner{}, errors.New("no certificates")
	}
	if !publicKeyMatchesCertificate(publicKeyDER, certs[0]) {
		return parsedSigner{}, errors.New("signer public key does not match leaf certificate")
	}

	digestBySignatureAlg := make(map[uint32][]byte, len(digestRecords))
	for _, digest := range digestRecords {
		if _, exists := digestBySignatureAlg[digest.ID]; exists {
			return parsedSigner{}, fmt.Errorf("duplicate digest record for signature algorithm ID 0x%04x", digest.ID)
		}
		digestBySignatureAlg[digest.ID] = digest.Value
	}

	var expectations []digestExpectation
	var algNames []string
	for _, alg := range verifiedAlgs {
		expectedDigest, ok := digestBySignatureAlg[alg.ID]
		if !ok {
			return parsedSigner{}, fmt.Errorf("missing content digest for %s", alg.Name)
		}
		expectations = append(expectations, digestExpectation{
			Algorithm:      alg.ContentDigest,
			SignatureAlgID: alg.ID,
			Value:          expectedDigest,
		})
		algNames = append(algNames, alg.Name)
	}

	fingerprint := sha256.Sum256(certs[0].Raw)
	return parsedSigner{
		Result: verifiedSigner{
			Algorithms:        algNames,
			Subject:           certs[0].Subject.String(),
			CertificateSHA256: fingerprint[:],
		},
		DigestExpectations: expectations,
		LeafCertRaw:        certs[0].Raw,
	}, nil
}

func verifySignedData(publicKey any, alg signatureAlgorithm, signedData []byte, signature []byte) error {
	if !alg.Hash.Available() {
		return fmt.Errorf("hash %s is not available", alg.Hash.String())
	}
	h := alg.Hash.New()
	_, _ = h.Write(signedData)
	digest := h.Sum(nil)

	switch alg.Kind {
	case signatureKindRSAPKCS1:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key, got %T", publicKey)
		}
		return rsa.VerifyPKCS1v15(key, alg.Hash, digest, signature)
	case signatureKindRSAPSS:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key, got %T", publicKey)
		}
		return rsa.VerifyPSS(key, alg.Hash, digest, signature, &rsa.PSSOptions{
			SaltLength: alg.PSSSaltLength,
			Hash:       alg.Hash,
		})
	case signatureKindECDSA:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ECDSA public key, got %T", publicKey)
		}
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature algorithm %s", alg.Name)
	}
}

func parseSignedData(signedData []byte) ([]*x509.Certificate, []intBytesPair, []uint32, error) {
	reader := newByteReader(signedData)
	digestsBytes, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse signed-data digests: %w", err)
	}
	certificatesBytes, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse signed-data certificates: %w", err)
	}
	additionalAttributesBytes, err := reader.readLengthPrefixedBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse signed-data additional attributes: %w", err)
	}
	if reader.hasRemaining() {
		return nil, nil, nil, fmt.Errorf("unexpected trailing signed-data bytes: %d", reader.remaining())
	}

	digests, err := parseIntBytesPairs(digestsBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse digest records: %w", err)
	}
	digestAlgorithmIDs := make([]uint32, 0, len(digests))
	seenDigestAlgorithmIDs := make(map[uint32]struct{}, len(digests))
	for _, digest := range digests {
		if _, exists := seenDigestAlgorithmIDs[digest.ID]; exists {
			return nil, nil, nil, fmt.Errorf("duplicate digest record for signature algorithm ID 0x%04x", digest.ID)
		}
		seenDigestAlgorithmIDs[digest.ID] = struct{}{}
		digestAlgorithmIDs = append(digestAlgorithmIDs, digest.ID)
	}

	certReader := newByteReader(certificatesBytes)
	var certs []*x509.Certificate
	for certReader.hasRemaining() {
		certDER, err := certReader.readLengthPrefixedBytes()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse certificate record: %w", err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if err := parseAdditionalAttributes(additionalAttributesBytes); err != nil {
		return nil, nil, nil, err
	}

	return certs, digests, digestAlgorithmIDs, nil
}

func parseAdditionalAttributes(data []byte) error {
	reader := newByteReader(data)
	for reader.hasRemaining() {
		record, err := reader.readLengthPrefixedBytes()
		if err != nil {
			return fmt.Errorf("parse additional attribute record: %w", err)
		}
		if len(record) < 4 {
			return fmt.Errorf("additional attribute record is too short: %d", len(record))
		}
	}
	return nil
}

func sameUint32Slice(left []uint32, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func verifyContentDigests(expectations []digestExpectation, sections ...[]byte) error {
	type digestKey struct {
		alg   contentDigestAlgorithm
		value string
	}
	seen := make(map[digestKey]struct{})
	computed := make(map[contentDigestAlgorithm][]byte)
	for _, expectation := range expectations {
		key := digestKey{alg: expectation.Algorithm, value: string(expectation.Value)}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		actual, ok := computed[expectation.Algorithm]
		if !ok {
			var err error
			actual, err = computeContentDigest(expectation.Algorithm, sections...)
			if err != nil {
				return err
			}
			computed[expectation.Algorithm] = actual
		}
		if !bytes.Equal(actual, expectation.Value) {
			return fmt.Errorf("content digest mismatch for signature algorithm ID 0x%04x", expectation.SignatureAlgID)
		}
	}
	return nil
}

func verifyPinnedCertificate(signers []parsedSigner, pinnedCerts []*certificate) error {
	if len(pinnedCerts) == 0 {
		return nil
	}
	for _, signer := range signers {
		for _, pinned := range pinnedCerts {
			if pinned != nil && bytes.Equal(signer.LeafCertRaw, pinned.Raw) {
				return nil
			}
		}
	}
	return errors.New("no signer certificate matched --cert")
}

func joinAlgorithmNames(names []string) string {
	return strings.Join(names, ",")
}

func formatHex(value []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}
