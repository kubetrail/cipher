package run

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubetrail/cipher/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type persistentFlagValues struct {
	ApplicationCredentials string `json:"applicationCredentials,omitempty"`
	Project                string `json:"project,omitempty"`
	Location               string `json:"location,omitempty"`
	Keyring                string `json:"keyring,omitempty"`
	Key                    string `json:"key,omitempty"`
	NoKms                  bool   `json:"noKms,omitempty"`
}

func getPersistentFlags(cmd *cobra.Command) persistentFlagValues {
	rootCmd := cmd.Root().PersistentFlags()
	b := filepath.Base

	_ = viper.BindPFlag(flags.GoogleProjectID, rootCmd.Lookup(b(flags.GoogleProjectID)))
	_ = viper.BindPFlag(flags.KmsLocation, rootCmd.Lookup(b(flags.KmsLocation)))
	_ = viper.BindPFlag(flags.KmsKeyring, rootCmd.Lookup(b(flags.KmsKeyring)))
	_ = viper.BindPFlag(flags.KmsKey, rootCmd.Lookup(b(flags.KmsKey)))
	_ = viper.BindPFlag(flags.GoogleApplicationCredentials, rootCmd.Lookup(b(flags.GoogleApplicationCredentials)))
	_ = viper.BindPFlag(flags.NoKms, rootCmd.Lookup(b(flags.NoKms)))

	_ = viper.BindEnv(flags.GoogleProjectID, "GOOGLE_PROJECT_ID")
	_ = viper.BindEnv(flags.KmsLocation, "KMS_LOCATION")
	_ = viper.BindEnv(flags.KmsKeyring, "KMS_KEYRING")
	_ = viper.BindEnv(flags.KmsKey, "KMS_KEY")

	applicationCredentials := viper.GetString(flags.GoogleApplicationCredentials)
	project := viper.GetString(flags.GoogleProjectID)
	location := viper.GetString(flags.KmsLocation)
	keyring := viper.GetString(flags.KmsKeyring)
	key := viper.GetString(flags.KmsKey)
	noKms := viper.GetBool(flags.NoKms)

	return persistentFlagValues{
		ApplicationCredentials: applicationCredentials,
		Project:                project,
		Location:               location,
		Keyring:                keyring,
		Key:                    key,
		NoKms:                  noKms,
	}
}

func setAppCredsEnvVar(applicationCredentials string) error {
	if len(applicationCredentials) > 0 {
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", applicationCredentials); err != nil {
			err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
			return err
		}
	}

	return nil
}
