package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyRSA(t *testing.T) {
	input := makeTestZip(t)
	signer := makeRSASigner(t)
	alg := mustSignatureAlgorithm("rsa-pkcs1-sha256")

	signed, result, err := signZipV2(input, signer, alg)
	if err != nil {
		t.Fatalf("signZipV2() error = %v", err)
	}
	if result.RemovedExistingSigningBlock {
		t.Fatal("first signing unexpectedly removed an existing signing block")
	}

	verifyResult, err := verifyZipV2(signed, []*certificate{{Raw: signer.Certificates[0].Raw}})
	if err != nil {
		t.Fatalf("verifyZipV2() error = %v", err)
	}
	if got := len(verifyResult.Signers); got != 1 {
		t.Fatalf("verified signer count = %d, want 1", got)
	}
	if got := verifyResult.Signers[0].Algorithms[0]; got != alg.Name {
		t.Fatalf("algorithm = %s, want %s", got, alg.Name)
	}

	stripped, ok, err := stripSigningBlockForTest(signed)
	if err != nil {
		t.Fatalf("stripSigningBlockForTest() error = %v", err)
	}
	if !ok {
		t.Fatal("stripSigningBlockForTest() did not find signing block")
	}
	if !bytes.Equal(stripped, input) {
		t.Fatal("stripping the generated signing block did not restore the original ZIP")
	}
}

func TestGeneratedSignedDataHasExactlyThreeFields(t *testing.T) {
	input := makeTestZip(t)
	signer := makeRSASigner(t)

	signed, _, err := signZipV2(input, signer, mustSignatureAlgorithm("rsa-pkcs1-sha256"))
	if err != nil {
		t.Fatalf("signZipV2() error = %v", err)
	}

	signedData, err := extractFirstSignedData(signed)
	if err != nil {
		t.Fatalf("extractFirstSignedData() error = %v", err)
	}
	fieldLengths, err := countLengthPrefixedFields(signedData)
	if err != nil {
		t.Fatalf("countLengthPrefixedFields() error = %v", err)
	}
	if got, want := len(fieldLengths), 3; got != want {
		t.Fatalf("signed data field count = %d (%v), want %d", got, fieldLengths, want)
	}
}

func TestSignAndVerifyECDSA(t *testing.T) {
	input := makeTestZip(t)
	signer := makeECDSASigner(t)
	alg := mustSignatureAlgorithm("ecdsa-sha256")

	signed, _, err := signZipV2(input, signer, alg)
	if err != nil {
		t.Fatalf("signZipV2() error = %v", err)
	}

	if _, err := verifyZipV2(signed, []*certificate{{Raw: signer.Certificates[0].Raw}}); err != nil {
		t.Fatalf("verifyZipV2() error = %v", err)
	}
}

func TestSignReplacesExistingSigningBlock(t *testing.T) {
	input := makeTestZip(t)
	rsaSigner := makeRSASigner(t)
	ecdsaSigner := makeECDSASigner(t)

	first, _, err := signZipV2(input, rsaSigner, mustSignatureAlgorithm("rsa-pkcs1-sha256"))
	if err != nil {
		t.Fatalf("first signZipV2() error = %v", err)
	}
	second, result, err := signZipV2(first, ecdsaSigner, mustSignatureAlgorithm("ecdsa-sha256"))
	if err != nil {
		t.Fatalf("second signZipV2() error = %v", err)
	}
	if !result.RemovedExistingSigningBlock {
		t.Fatal("second signing did not report replacing an existing signing block")
	}

	if _, err := verifyZipV2(second, []*certificate{{Raw: ecdsaSigner.Certificates[0].Raw}}); err != nil {
		t.Fatalf("verifyZipV2(second) error = %v", err)
	}
	if _, err := verifyZipV2(second, []*certificate{{Raw: rsaSigner.Certificates[0].Raw}}); err == nil {
		t.Fatal("verifyZipV2(second, old cert) succeeded, want failure")
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	input := makeTestZip(t)
	signer := makeRSASigner(t)
	signed, _, err := signZipV2(input, signer, mustSignatureAlgorithm("rsa-pss-sha256"))
	if err != nil {
		t.Fatalf("signZipV2() error = %v", err)
	}

	tampered := append([]byte(nil), signed...)
	index := bytes.Index(tampered, []byte("hello from ziplac"))
	if index < 0 {
		t.Fatal("test payload not found")
	}
	tampered[index] ^= 0xff

	if _, err := verifyZipV2(tampered, nil); err == nil {
		t.Fatal("verifyZipV2(tampered) succeeded, want failure")
	}
}

func TestVerifyRejectsExtraSignedDataField(t *testing.T) {
	input := makeTestZip(t)
	signer := makeRSASigner(t)
	alg := mustSignatureAlgorithm("rsa-pkcs1-sha256")

	signed, err := signZipV2WithSignedDataBuilder(input, signer, alg, func(certs []*x509.Certificate, alg signatureAlgorithm, contentDigest []byte) ([]byte, error) {
		signedData, err := buildSignedData(certs, alg, contentDigest)
		if err != nil {
			return nil, err
		}
		return append(signedData, encodeLengthPrefixed(nil)...), nil
	})
	if err != nil {
		t.Fatalf("signZipV2WithSignedDataBuilder() error = %v", err)
	}

	if _, err := verifyZipV2(signed, nil); err == nil {
		t.Fatal("verifyZipV2() accepted signed data with an extra empty field")
	}
}

func TestVerifyRejectsSignatureDigestAlgorithmIDMismatch(t *testing.T) {
	input := makeTestZip(t)
	signer := makeRSASigner(t)
	alg := mustSignatureAlgorithm("rsa-pkcs1-sha256")

	signed, err := signZipV2WithSignedDataBuilder(input, signer, alg, func(certs []*x509.Certificate, _ signatureAlgorithm, contentDigest []byte) ([]byte, error) {
		certBytes := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			certBytes = append(certBytes, cert.Raw)
		}
		digests := encodeIntBytesPairs([]intBytesPair{{ID: alg.ID + 1, Value: contentDigest}})
		certificates := encodeSequence(certBytes)
		return encodeSequence([][]byte{digests, certificates, nil}), nil
	})
	if err != nil {
		t.Fatalf("signZipV2WithSignedDataBuilder() error = %v", err)
	}

	if _, err := verifyZipV2(signed, nil); err == nil {
		t.Fatal("verifyZipV2() accepted mismatched signature/digest algorithm ID lists")
	}
}

func TestCLIPEMSignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.zip")
	outputPath := filepath.Join(tmpDir, "signed.zip")
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")

	if err := os.WriteFile(inputPath, makeTestZip(t), 0o644); err != nil {
		t.Fatalf("write input ZIP: %v", err)
	}
	signer := makeRSASigner(t)
	rsaKey := signer.PrivateKey.(*rsa.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificates[0].Raw})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	signCmd := newRootCommand()
	signCmd.SetOut(io.Discard)
	signCmd.SetArgs([]string{"sign", inputPath, outputPath, "--key", keyPath, "--cert", certPath})
	if err := signCmd.Execute(); err != nil {
		t.Fatalf("ziplac sign error = %v", err)
	}

	var output bytes.Buffer
	verifyCmd := newRootCommand()
	verifyCmd.SetOut(&output)
	verifyCmd.SetArgs([]string{"verify", outputPath, "--cert", certPath})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("ziplac verify error = %v", err)
	}
	if !strings.Contains(output.String(), "OK: verified 1 signer") {
		t.Fatalf("verify output = %q", output.String())
	}
}

type signedDataBuilder func([]*x509.Certificate, signatureAlgorithm, []byte) ([]byte, error)

func signZipV2WithSignedDataBuilder(input []byte, signer signerConfig, alg signatureAlgorithm, builder signedDataBuilder) ([]byte, error) {
	info, err := inspectZip(input)
	if err != nil {
		return nil, err
	}
	signingBlock, hasSigningBlock, err := findSigningBlock(input, info.CentralDirOffset)
	if err != nil {
		return nil, err
	}

	beforeEnd := info.CentralDirOffset
	if hasSigningBlock {
		beforeEnd = signingBlock.Offset
	}
	before := input[:beforeEnd]
	centralDir := input[info.CentralDirOffset:info.EOCDOffset]
	eocdForDigest := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(eocdForDigest, uint64(len(before))); err != nil {
		return nil, err
	}

	contentDigest, err := computeContentDigest(alg.ContentDigest, before, centralDir, eocdForDigest)
	if err != nil {
		return nil, err
	}
	signedData, err := builder(signer.Certificates, alg, contentDigest)
	if err != nil {
		return nil, err
	}
	signature, err := signSignedData(signer, alg, signedData)
	if err != nil {
		return nil, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(signer.Certificates[0].PublicKey)
	if err != nil {
		return nil, err
	}

	signatures := encodeIntBytesPairs([]intBytesPair{{ID: alg.ID, Value: signature}})
	signerBlock := encodeSequence([][]byte{signedData, signatures, publicKeyDER})
	signers := encodeSequence([][]byte{signerBlock})
	newSigningBlock := buildSigningBlock(encodeSequence([][]byte{signers}))
	finalCentralDirOffset := uint64(len(before) + len(newSigningBlock))
	if finalCentralDirOffset > math.MaxUint32 {
		return nil, fmt.Errorf("central directory offset after signing exceeds ZIP32 limit: %d", finalCentralDirOffset)
	}
	finalEOCD := append([]byte(nil), input[info.EOCDOffset:]...)
	if err := setEOCDCentralDirectoryOffset(finalEOCD, finalCentralDirOffset); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(before)+len(newSigningBlock)+len(centralDir)+len(finalEOCD))
	out = append(out, before...)
	out = append(out, newSigningBlock...)
	out = append(out, centralDir...)
	out = append(out, finalEOCD...)
	return out, nil
}

func extractFirstSignedData(input []byte) ([]byte, error) {
	info, err := inspectZip(input)
	if err != nil {
		return nil, err
	}
	signingBlock, ok, err := findSigningBlock(input, info.CentralDirOffset)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("APK Signing Block not found")
	}
	v2Block, err := findV2Block(signingBlock.Block)
	if err != nil {
		return nil, err
	}
	v2Reader := newByteReader(v2Block)
	signersBytes, err := v2Reader.readLengthPrefixedBytes()
	if err != nil {
		return nil, err
	}
	signersReader := newByteReader(signersBytes)
	signerBytes, err := signersReader.readLengthPrefixedBytes()
	if err != nil {
		return nil, err
	}
	signerReader := newByteReader(signerBytes)
	return signerReader.readLengthPrefixedBytes()
}

func countLengthPrefixedFields(data []byte) ([]int, error) {
	reader := newByteReader(data)
	var lengths []int
	for reader.hasRemaining() {
		field, err := reader.readLengthPrefixedBytes()
		if err != nil {
			return nil, err
		}
		lengths = append(lengths, len(field))
	}
	return lengths, nil
}

func makeTestZip(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"hello.txt": "hello from ziplac",
		"dir/a.txt": "another file",
	} {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("create ZIP entry: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write ZIP entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close ZIP: %v", err)
	}
	return buf.Bytes()
}

func makeRSASigner(t *testing.T) signerConfig {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return makeSignerForKey(t, key)
}

func makeECDSASigner(t *testing.T) signerConfig {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return makeSignerForKey(t, key)
}

func makeSignerForKey(t *testing.T, key any) signerConfig {
	t.Helper()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ziplac test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("key %T is not a crypto.Signer", key)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return signerConfig{PrivateKey: signer, Certificates: []*x509.Certificate{cert}}
}
