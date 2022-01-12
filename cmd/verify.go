/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"path/filepath"

	"github.com/kubetrail/cipher/pkg/flags"
	"github.com/kubetrail/cipher/pkg/run"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signature",
	Long:  `Verify signature on data`,
	RunE:  run.Verify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	f := verifyCmd.Flags()
	b := filepath.Base

	f.String(b(flags.KeyFile), "id_rsa.pub", "Public key file")
	f.String(b(flags.PlainText), "", "Plaintext file")
	f.String(b(flags.Signature), "", "Signature file")
}
