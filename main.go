package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ziplac",
		Short: "Sign and verify ZIP files using APK Signature Scheme v2",
	}

	root.AddCommand(newSignCommand())
	root.AddCommand(newVerifyCommand())
	return root
}

type signOptions struct {
	in        string
	out       string
	key       string
	cert      string
	keyPass   string
	p12       string
	p12Pass   string
	alg       string
	overwrite bool
}

func newSignCommand() *cobra.Command {
	var opts signOptions
	cmd := &cobra.Command{
		Use:   "sign [input.zip] [output.zip]",
		Short: "Sign a ZIP file",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.in == "" {
				opts.in = args[0]
			}
			if len(args) > 1 && opts.out == "" {
				opts.out = args[1]
			}
			if opts.in == "" {
				return errors.New("input ZIP is required")
			}
			if opts.out == "" {
				return errors.New("output ZIP is required")
			}
			if !opts.overwrite {
				if _, err := os.Stat(opts.out); err == nil {
					return fmt.Errorf("output file already exists: %s (use --overwrite)", opts.out)
				} else if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("stat output file: %w", err)
				}
			}

			signer, err := loadSigner(loadSignerOptions{
				keyPath:  opts.key,
				certPath: opts.cert,
				keyPass:  opts.keyPass,
				p12Path:  opts.p12,
				p12Pass:  opts.p12Pass,
			})
			if err != nil {
				return err
			}

			alg, err := selectSignatureAlgorithm(signer.PrivateKey, opts.alg)
			if err != nil {
				return err
			}

			input, err := os.ReadFile(opts.in)
			if err != nil {
				return fmt.Errorf("read input ZIP: %w", err)
			}

			signed, result, err := signZipV2(input, signer, alg)
			if err != nil {
				return err
			}
			if err := os.WriteFile(opts.out, signed, 0o644); err != nil {
				return fmt.Errorf("write output ZIP: %w", err)
			}

			removed := ""
			if result.RemovedExistingSigningBlock {
				removed = " (replaced existing APK Signing Block)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed %s -> %s with %s%s\n", opts.in, opts.out, alg.Name, removed)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.in, "in", "i", "", "input ZIP path")
	flags.StringVarP(&opts.out, "out", "o", "", "output ZIP path")
	flags.StringVar(&opts.key, "key", "", "PEM private key path")
	flags.StringVar(&opts.cert, "cert", "", "PEM certificate or chain path")
	flags.StringVar(&opts.keyPass, "key-pass", "", "password for encrypted PEM private key")
	flags.StringVar(&opts.p12, "p12", "", "PKCS#12/PFX signer path")
	flags.StringVar(&opts.p12Pass, "p12-pass", "", "password for PKCS#12/PFX signer")
	flags.StringVar(&opts.alg, "alg", "auto", "signature algorithm: auto, rsa-pkcs1-sha256, rsa-pkcs1-sha512, rsa-pss-sha256, rsa-pss-sha512, ecdsa-sha256, ecdsa-sha512")
	flags.BoolVar(&opts.overwrite, "overwrite", false, "overwrite output file if it exists")
	return cmd
}

type verifyOptions struct {
	in   string
	cert string
}

func newVerifyCommand() *cobra.Command {
	var opts verifyOptions
	cmd := &cobra.Command{
		Use:   "verify [signed.zip]",
		Short: "Verify a ZIP file signature",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.in == "" {
				opts.in = args[0]
			}
			if opts.in == "" {
				return errors.New("input ZIP is required")
			}

			var pinnedCerts []*certificate
			if opts.cert != "" {
				certs, err := loadCertificates(opts.cert)
				if err != nil {
					return err
				}
				for _, cert := range certs {
					pinnedCerts = append(pinnedCerts, &certificate{Raw: cert.Raw})
				}
			}

			input, err := os.ReadFile(opts.in)
			if err != nil {
				return fmt.Errorf("read input ZIP: %w", err)
			}

			result, err := verifyZipV2(input, pinnedCerts)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "OK: verified %d signer(s)\n", len(result.Signers))
			for i, signer := range result.Signers {
				fmt.Fprintf(
					cmd.OutOrStdout(),
					"signer %d: alg=%s subject=%q cert_sha256=%s\n",
					i+1,
					joinAlgorithmNames(signer.Algorithms),
					signer.Subject,
					formatHex(signer.CertificateSHA256),
				)
			}
			if opts.cert == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "note: signer identity was verified against the embedded certificate only; use --cert to pin an expected certificate")
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.in, "in", "i", "", "signed ZIP path")
	flags.StringVar(&opts.cert, "cert", "", "PEM certificate path that must match at least one signer")
	return cmd
}
