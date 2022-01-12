package run

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kubetrail/cipher/pkg/crypto"
	"github.com/kubetrail/cipher/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Verify(cmd *cobra.Command, _ []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindPFlag(flags.Signature, cmd.Flags().Lookup(filepath.Base(flags.Signature)))
	_ = viper.BindPFlag(flags.PlainText, cmd.Flags().Lookup(filepath.Base(flags.PlainText)))

	keyFile := viper.GetString(flags.KeyFile)
	signature := viper.GetString(flags.Signature)
	plainText := viper.GetString(flags.PlainText)

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	if keyFile == "-" {
		return fmt.Errorf("key input via STDIN is not allowed")
	}

	if signature == "-" {
		return fmt.Errorf("signature input via STDIN is not allowed")
	}

	b, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("could not read keyfile: %w", err)
	}

	key, err := crypto.BytesToPublicKey(b)
	if err != nil {
		return fmt.Errorf("could not derive public key from bytes: %w", err)
	}

	var r io.Reader

	if plainText == "-" {
		r = cmd.InOrStdin()
		if signature == "" {
			return fmt.Errorf("please input a signature file name")
		}
	} else {
		f, err := os.Open(plainText)
		if err != nil {
			return fmt.Errorf("could not open plaintext file: %w", err)
		}
		defer f.Close()
		r = f
		if signature == "" {
			signature = fmt.Sprintf("%s.sig", plainText)
		}
	}

	sig, err := os.ReadFile(signature)
	if err != nil {
		return fmt.Errorf("could not read signature file: %w", err)
	}

	if err := crypto.VerifySignature(r, sig, key); err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}

	return nil
}
