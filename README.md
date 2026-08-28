# sops-cli

`sops-cli` is a small command-line wrapper around [Mozilla SOPS](https://github.com/getsops/sops). It encrypts and decrypts JSON, YAML, and binary secret files using PGP or AWS KMS master keys.

Encrypted data is handled by SOPS and uses AES-256-GCM for the payload. The selected master key protects the generated data key, and key metadata is stored in the encrypted SOPS document. Therefore, decryption discovers the required key from the input file.

## Features

- Encrypt JSON, YAML, or binary files.
- Decrypt SOPS files to JSON, YAML, or binary output.
- Convert formats while decrypting, such as YAML to JSON.
- Write results to a file or print them to stdout.
- Use one or more comma-separated PGP fingerprints or AWS KMS key ARNs for encryption.
- Write output files with owner-only permissions (`0600`).

## Requirements

- Go 1.27 or later.
- A PGP private key available to the local SOPS/GPG environment when using PGP.
- AWS credentials and permission to use the KMS key when using AWS KMS. The standard AWS SDK credential chain is used.

The repository also provides a [mise](https://mise.jdx.dev/) configuration for Go, `golangci-lint`, `gofumpt`, AWS CLI, and other development tools used by CI.

## Installation

Build from a checkout:

```sh
git clone https://github.com/aniruddha-sinha/sops-cli.git
cd sops-cli
go build -o sops-cli .
```

Or install the Go module directly:

```sh
go install github.com/aniruddha-sinha/sops-cli@latest
```

Tagged releases are built by GoReleaser for Linux, macOS, and Windows on `amd64` and `arm64`. Release binaries use names such as `sops-cli-linux-amd64`.

## Usage

The general forms are:

```sh
sops-cli encrypt --in INPUT --key-type KEY_TYPE --key KEY [--format FORMAT] [--out OUTPUT]
sops-cli decrypt --in INPUT [--in-format FORMAT] [--out-format FORMAT] [--out OUTPUT]
```

`e` and `d` are aliases for `encrypt` and `decrypt`. Supported formats are `json`, `yaml`, and `binary`; format names are case-insensitive. If `--out` is omitted, output is written to stdout.

### Encrypt with PGP

Use the fingerprint of a public PGP key. Multiple fingerprints may be supplied as a comma-separated value.

```sh
sops-cli encrypt \
  --in secret.json \
  --format json \
  --key-type pgp \
  --key "0123456789ABCDEF0123456789ABCDEF01234567" \
  --out secret.enc.json
```

### Encrypt with AWS KMS

Pass the KMS key ARN as `--key`. Configure AWS credentials using the standard AWS SDK mechanisms before running the command.

```sh
sops-cli encrypt \
  --in secret.json \
  --format json \
  --key-type kms \
  --key "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID" \
  --out secret.enc.json
```

### Decrypt

The encrypted file contains its SOPS key metadata, so decryption only requires the input path and formats:

```sh
sops-cli decrypt \
  --in secret.enc.json \
  --in-format json \
  --out-format json \
  --out secret.json
```

Format conversion is supported during decryption:

```sh
sops-cli decrypt \
  --in secret.enc.yaml \
  --in-format yaml \
  --out-format json \
  --out secret.json
```

Binary payloads can be decrypted as follows:

```sh
sops-cli decrypt \
  --in archive.enc.bin \
  --in-format binary \
  --out-format binary \
  --out archive.bin
```

When using stdout, remember that the result is plaintext and may be captured in shell history, logs, pipes, or terminal scrollback.

## Command reference

### `encrypt` / `e`

| Flag | Default | Description |
| --- | --- | --- |
| `--in` | required | Plaintext input file. |
| `--out` | stdout | Encrypted output file. |
| `--format` | `json` | Input format: `json`, `yaml`, or `binary`. |
| `--key-type` | required | Master-key provider: `pgp` or `kms`. |
| `--key` | required | PGP fingerprint, KMS ARN, or comma-separated key specifications. |

### `decrypt` / `d`

| Flag | Default | Description |
| --- | --- | --- |
| `--in` | required | SOPS-encrypted input file. |
| `--out` | stdout | Plaintext output file. |
| `--in-format` | `json` | Format of the encrypted input. |
| `--out-format` | `json` | Desired plaintext output format. |

## Repository examples

The `example/` directory contains checked-in sample inputs and outputs grouped by operation, provider, format, and data type:

```text
example/
├── encryption/
│   ├── example-pgp/
│   └── example-aws-kms/
└── decryption/
    ├── example-pgp/
    └── example-aws-kms/
```

The AWS KMS samples require access to the referenced KMS key to decrypt. The PGP samples require the corresponding private key.

## Code organization

```text
.
├── main.go                 # Application entry point
├── cmd/
│   ├── root.go             # Root Cobra command and shared behavior
│   └── sops.go             # encrypt and decrypt commands/flags
├── internal/sops/
│   ├── encrypt.go          # SOPS tree creation and encryption
│   ├── decrypt.go          # SOPS decryption and format conversion
│   ├── validator.go        # File, format, and master-key validation
│   └── common.go           # Secure output-file writing
├── example/                # Sample encrypted/decrypted files
└── .github/workflows/      # CI and tagged-release workflows
```

Encryption reads the plaintext with the selected SOPS store, creates a SOPS tree with an `_unencrypted` suffix, generates a data key, encrypts the tree with AES-256-GCM, and emits the selected format. Decryption reads and decrypts the SOPS document, then optionally loads and emits it through different SOPS stores for format conversion.

## Development

Run the standard Go checks:

```sh
go test ./...
go vet ./...
golangci-lint run ./...
gofumpt -w .
```

With mise installed:

```sh
mise install
mise run test:run       # Tests and coverage profile
mise run test:coverage  # HTML coverage report
mise run build          # Build into bin/
mise run lint           # Lint and format
mise run all            # Clean, lint, test, coverage, and build
```

GitHub Actions runs `mise --verbose run all` for pushes and pull requests targeting `main`. A tag matching `v*.*.*` starts the GoReleaser release workflow.

## Security notes

- Treat decrypted output and stdout as sensitive plaintext.
- Output files are created or truncated and restricted to mode `0600` before plaintext is written.
- Do not run the CLI as root unless it is intentional; the application warns when it detects a root user.
- Do not commit real secrets, private keys, or credentials.

## License

See [LICENSE](LICENSE). The current repository license file is empty.
