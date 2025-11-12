# YubiKey CA

These two scripts simplify creating and signing certificates using a **YubiKey PIV** (slot 9c) as a signing device. One script is for **web server certificates**; the other is for **client TLS certificates**. Currently supports P-256 and P-384.

---

## Scripts

### 1. `mk-piv-webcert.sh`

* **Purpose**: Generate and sign a **web server certificate** (EKU = `serverAuth`) using a YubiKey PIV.
* **Usage**:

```bash
./mk-piv-webcert.sh <CN> [IP] [CURVE]
```

* **Parameters**:

  * `CN` (required) — Common Name and output folder name.
  * `IP` (optional) — IP address for Subject Alternative Name (SAN).
  * `CURVE` (optional) — ECC curve name, defaults to secpr384r1
* **Behavior**:

  * Generates an ECC key + CSR locally.
  * Signs CSR with YubiKey PIV CA key (slot 9c via PKCS#11).
  * Generates output files in `<CN>/`:

    * `CN.crt` — certificate
    * `CN.fullchain.pem` — CRT + CA chain
    * `CN.p12` — PKCS#12 bundle
    * `CN.zip` — zipped folder
  * Uses a **32-character password** for private key protection.
  * Exports PFX/P12 bundle protected using a **16-character password** (Windows has issues importing bundles with longer passwords)
  * Optionally prints the decrypted private key if `PRINT_KEY=1`.
  * Cleans up private key and temporary files.

---

### 2. `mk-piv-client-cert.sh`

* **Purpose**: Generate and sign a **TLS client certificate** (EKU = `clientAuth`) using YubiKey PIV.
* **Usage**:

```bash
./mk-piv-client-cert.sh <CN> [EMAIL] [CURVE]
```

* **Parameters**:

  * `CN` (required) — Common Name and output folder name.
  * `EMAIL` (optional) — Email for SAN (`rfc822Name`) and DN (`emailAddress`).
  * `CURVE` (optional) — ECC curve name, defaults to secpr384r1
* **Behavior**:

  * Generates an RSA key + CSR locally.
  * Signs CSR with YubiKey PIV CA key.
  * Generates output files in `<CN>/` (same as web script).
  * Uses a **32-character password** for private key protection.
  * Exports PFX/P12 bundle protected using a **16-character password** (Windows has issues importing bundles with longer passwords)
  * Cleans up temporary and sensitive files.

---

## Common Features

* **Environment Variables** (can override defaults):

  * `RSA_BITS` — key size
  * `CA_CERT` — path to CA certificate
  * `DAYS` — validity in days (default 1825)
  * `CA_KEY_URI` — PKCS#11 URI for CA private key
  * `OUTDIR` — output directory
  * `PKCS11_MODULE_PATH` — path to `libykcs11.so`
  * `PRINT_KEY` — print decrypted private key (web script only)

* **Dependencies**:

  * `openssl`
  * `zip`
  * Optional: `shred` for secure deletion of private key.

---

## Security notes
  
  * Private key is generated encrypted with a random password (then securely deleted from disk).
  * Random password is used for protecting the PFX/P12 export (using AES256-CBC as cipher).
  * Temporary and sensitive files are removed automatically.
  * Sensitive information (private key, PFX/P12 bundle password) gets printed to `/dev/tty` (to fight output redirection and log snooping).
  * Decrypted private key is only printed if explicitly requested (web script only).
  * CA key **never leaves** the YubiKey, signing operations are handled by the secure element.
---

## Example Usage

**Web certificate**:

```bash
export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/libykcs11.so
./mk-piv-webcert.sh ap.example.local 10.0.0.5 4096
# Outputs in ./ap.example.local/
```

**Client certificate**:

```bash
export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/libykcs11.so
./mk-piv-client-cert.sh alice alice@example.com 4096
# P12 password printed once; outputs in ./alice/
```

---

## Output Files

| File               | Description                                      |
| ------------------ | ------------------------------------------------ |
| `CN.crt`           | Signed certificate                               |
| `CN.fullchain.pem` | Certificate + CA chain                           |
| `CN.p12`           | PKCS#12 bundle (protected by random password)    |
| `CN.zip`           | Zip of folder contents                           |
| `CN.key`           | Encrypted RSA private key (deleted after script) |

---

## Notes

* The scripts **require a YubiKey PIV with the CA key** in slot 9c (Digital Signature).
