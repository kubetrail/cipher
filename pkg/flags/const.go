package flags

const (
	GoogleProjectID              = "google-project-id"              // Google KMS project ID
	KmsLocation                  = "kms-location"                   // KMS location for the key and keyring
	KmsKeyring                   = "kms-keyring"                    // KMS keyring name
	KmsKey                       = "kms-key"                        // KMS key name
	GoogleApplicationCredentials = "google-application-credentials" // Google service account with KMS encrypter/decrypter role
	KeyFile                      = "key"                            // key file name
	NoKms                        = "no-kms"                         // do not use KMS
	CipherText                   = "ciphertext"                     // cipher text file name
	PlainText                    = "plaintext"                      // plain text file name
	Signature                    = "signature"                      // signature file
)
