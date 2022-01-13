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

func Encrypt(cmd *cobra.Command, _ []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindPFlag(flags.CipherText, cmd.Flags().Lookup(filepath.Base(flags.CipherText)))
	_ = viper.BindPFlag(flags.PlainText, cmd.Flags().Lookup(filepath.Base(flags.PlainText)))

	_ = viper.BindEnv(flags.KeyFile, "PUBLIC_KEY")

	keyFile := viper.GetString(flags.KeyFile)
	cipherText := viper.GetString(flags.CipherText)
	plainText := viper.GetString(flags.PlainText)

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	if keyFile == "-" {
		return fmt.Errorf("key input via STDIN is not allowed")
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
	var w io.Writer

	if plainText == "-" {
		r = cmd.InOrStdin()
		if cipherText == "" {
			cipherText = "-"
		}
	} else {
		f, err := os.Open(plainText)
		if err != nil {
			return fmt.Errorf("could not open plaintext file: %w", err)
		}
		defer f.Close()
		r = f
		if cipherText == "" {
			cipherText = fmt.Sprintf("%s.ciphertext", plainText)
		}
	}

	if cipherText == "-" {
		w = cmd.OutOrStdout()
	} else {
		f, err := os.Create(cipherText)
		if err != nil {
			return fmt.Errorf("could not open ciphertext file: %w", err)
		}
		defer f.Close()
		w = f
	}

	if err := crypto.EncryptData(r, w, key); err != nil {
		return fmt.Errorf("could not encrypt plaintext data: %w", err)
	}

	return nil
}
