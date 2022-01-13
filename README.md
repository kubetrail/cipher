# cipher
`cipher` is an industrial grade data encryption tool that uses several
layers of encryption. Data is encrypted using data encryption keys (DEK),
which are in turn encrypted using key encryption key (KEK), which in
turn is encrypted using Google KMS. This ensures that plaintext keys are
never persisted on the disk unless KMS functionality is explicitly turned off.

The tool is also performant splitting the data into chunks and processing
each chunk concurrently. Furthermore, different types of encryption algorithms
are uses at different levels to ensure large files can be easily encrypted.

For instance, a 16GB plaintext can be encrypted in under a minute. DEK is
done using AES and KEK is performed using RSA.

## installation
Download this repo to a folder and cd to it. Make sure `go` toolchain
is installed
```bash
go install
```
Add autocompletion for `bash` to your `.bashrc`
```bash
source <(cipher completion bash)
```

## usage
### generate keys
Generate new RSA keypair:
```bash
cipher keygen --no-kms
```
This command will output two files `id_rsa` (private key) and `id_rsa.pub`
(public key). Both keys are PEM encoded, however since `--no-kms` flag was
used, the private key is stored on the disk in plaintext and not
encrypted using Google KMS.

In order to persist the private key encrypted by KMS, set following env.
variables:

```bash
export KMS_LOCATION=your-kms-key-location
export KMS_KEYRING=your-kms-keyring-name
export KMS_KEY=your-kms-key-name
export GOOGLE_PROJECT_ID=your-project-id
export GOOGLE_APPLICATION_CREDENTIALS=service-account-file.json
```
Now keys can be generated such that the public key is PEM encoded, however
the private key is encrypted by KMS:
```bash
cipher keygen
```

For ease of use you can set key paths as env. vars:
```bash
export PUBLIC_KEY="/path/to/id_rsa.pub"
export PRIVATE_KEY="/path/to/id_rsa"
```

### encrypt data
Generate a random data first:
```bash
openssl rand -out sample.txt -base64 $(( 2**30 * 3/4 ))
```
Encrypt data
```bash
cipher encrypt --plaintext=sample.txt
```
This will create a file called `sample.txt.ciphertext`, which is the encrypted file.

> Read architectural notes below on format of the encrypted file performance over large 
> files.

Encryption is performed only using public key. The default public key is `id_rsa.pub`,
however, a public key filename can be provided on the command line input as needed.

### decrypt data
```bash
cipher decrypt --ciphertext=sample.txt.ciphertext
```

Decryption is performed only using private key. The default private key is `id_rsa`,
however, a private key filename can be provided on the command line input as needed.

Verify the decrypted data matches original input data
```bash
md5sum sample.txt sample.txt.ciphertext.plaintext 
11ca579e5b08b5f3dcce15a09d259103  sample.txt
11ca579e5b08b5f3dcce15a09d259103  sample.txt.ciphertext.plaintext
```

### sign data
```bash
cipher sign --plaintext=sample.txt
```

Data signing is performed using private key, where the default private key is `id_rsa` and
the default output signature filename is `.sig` appended to the input plaintext filename.

### verify data
```bash
cipher verify --plaintext=sample.txt
```

Data verification is done using public key. The default public key is `id_rsa.pub` and the
default signature filename is `.sig` appended to the input plaintext filename.

## architecture
### performance
Input data is typically split into chunks are processed in multiple threads concurrently for
improved performance.

Let's create a large file:
```bash
openssl rand -out sample.txt -base64 $(( 2**30 * 3/4 ))
```
This creates a 1GB file:
```bash
du -hs sample.txt
1.1G	sample.txt
```

Appending the file over and over creates a large file
```bash
for d in {1..16}; do cat sample.txt >> large-file.txt; done
du -hs large-file.txt 
17G	large-file.txt
```

```bash
time cipher encrypt --plaintext=large-file.txt 

real	0m19.872s
user	0m52.867s
sys	0m27.807s
```

```bash
time cipher sign --plaintext=large-file.txt 

real	0m46.508s
user	0m52.756s
sys	0m3.531s
```

### ciphertext format
Encrypted data is stored in sequence of json documents each representing a separately
encrypted chunk of plaintext data. Each chunk is encrypted using a separate symmetric AES key,
i.e. a data encryption key DEK. RSA public key is used as the key encryption key (KEK)
to encrypt the DEK. Encrypted DEK is stored next to the encrypted data chunk.
