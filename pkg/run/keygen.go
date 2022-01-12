package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubetrail/cipher/pkg/crypto"
	"github.com/kubetrail/cipher/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Keygen(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))

	keyFile := viper.GetString(flags.KeyFile)

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.DefaultBits2048)
	if err != nil {
		return fmt.Errorf("could not generate RSA keypairs: %w", err)
	}

	privBytes := crypto.PrivateKeyToBytes(priv)
	pubBytes, err := crypto.PublicKeyToBytes(pub)
	if err != nil {
		return fmt.Errorf("could not generate PEM for public key: %w", err)
	}

	if !persistentFlags.NoKms {
		privBytes, err = crypto.EncryptWithKms(
			ctx,
			privBytes,
			persistentFlags.Project,
			persistentFlags.Location,
			persistentFlags.Keyring,
			persistentFlags.Key,
		)
		if err != nil {
			return fmt.Errorf("could not encrypt private key via KMS: %w", err)
		}
	}

	if keyFile == "-" {
		if persistentFlags.NoKms {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(privBytes))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(pubBytes))
		} else {
			jb, err := json.Marshal(
				struct {
					PrivateKey []byte `json:"privateKey,omitempty"`
					PublicKey  []byte `json:"publicKey,omitempty"`
				}{
					PrivateKey: privBytes,
					PublicKey:  pubBytes,
				},
			)
			if err != nil {
				return fmt.Errorf("could not serialize output for keys: %w", err)
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(jb))
		}

		return nil
	}

	if err := os.WriteFile(keyFile, privBytes, 0600); err != nil {
		return fmt.Errorf("could not write private key to file: %w", err)
	}

	if err := os.WriteFile(fmt.Sprintf("%s.pub", keyFile), pubBytes, 0600); err != nil {
		return fmt.Errorf("could not write public key to file: %w", err)
	}

	return nil
}
