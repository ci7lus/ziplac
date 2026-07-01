# ziplac

`ziplac` signs and verifies ordinary ZIP files using the APK Signature Scheme v2 block format.

It intentionally covers only ZIP whole-file signing:

- no APK manifest parsing
- no v1/v3/v4 APK schemes
- no ZIP64 support
- no verity padding or APK install-time policy checks

## Build

```sh
go build ./...
```

## Sign

```sh
go run . sign input.zip output.zip --key private.pem --cert certificate.pem
go run . sign input.zip output.zip --p12 signer.p12 --p12-pass password
```

By default `--alg=auto` selects RSA/PKCS#1 v1.5 or ECDSA with SHA-256/SHA-512 based on the key.
Explicit algorithms are also available:

- `rsa-pkcs1-sha256`
- `rsa-pkcs1-sha512`
- `rsa-pss-sha256`
- `rsa-pss-sha512`
- `ecdsa-sha256`
- `ecdsa-sha512`

## Verify

```sh
go run . verify output.zip
go run . verify output.zip --cert certificate.pem
```

Without `--cert`, verification proves integrity against the embedded signing certificate. Use
`--cert` when the signer identity must be pinned.

## License

Apache-2.0. See `LICENSE`.

This implementation was written with reference to the Android Open Source
Project APK Signature Scheme v2 documentation and the AOSP `apksig` reference
implementation. See `NOTICE` for attribution details.
