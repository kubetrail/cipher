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

func Decrypt(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindPFlag(flags.CipherText, cmd.Flags().Lookup(filepath.Base(flags.CipherText)))
	_ = viper.BindPFlag(flags.PlainText, cmd.Flags().Lookup(filepath.Base(flags.PlainText)))

	_ = viper.BindEnv(flags.KeyFile, "PRIVATE_KEY")

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

	if cipherText == "" {
		return fmt.Errorf("please enter ciphertext file")
	}

	b, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("could not read keyfile: %w", err)
	}

	if !persistentFlags.NoKms {
		b, err = crypto.DecryptWithKms(
			ctx,
			b,
			persistentFlags.Project,
			persistentFlags.Location,
			persistentFlags.Keyring,
			persistentFlags.Key,
		)
		if err != nil {
			return fmt.Errorf("could not decrypt key using KMS: %w", err)
		}
	}

	key, err := crypto.BytesToPrivateKey(b)
	if err != nil {
		return fmt.Errorf("could not derive private key from bytes: %w", err)
	}

	var r io.Reader
	var w io.Writer

	if cipherText == "-" {
		w = cmd.OutOrStdout()
		if plainText == "" {
			plainText = "-"
		}
	} else {
		f, err := os.Open(cipherText)
		if err != nil {
			return fmt.Errorf("could not open ciphertext file: %w", err)
		}
		defer f.Close()
		r = f
		if plainText == "" {
			plainText = fmt.Sprintf("%s.plaintext", cipherText)
		}
	}

	if plainText == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Create(plainText)
		if err != nil {
			return fmt.Errorf("could not open plaintext file: %w", err)
		}
		defer f.Close()
		w = f
	}

	if err := crypto.DecryptData(r, w, key); err != nil {
		return fmt.Errorf("could not decrypt ciphertext data: %w", err)
	}

	return nil
}
