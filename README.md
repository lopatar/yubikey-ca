# README — YubiKey CA

These two scripts simplify creating and signing certificates using a **YubiKey PIV** (slot 9c) as a signing device. One script is for **web server certificates**; the other is for **client TLS certificates**.

---

## Scripts

### 1. `mk-piv-webcert.sh`

* **Purpose**: Generate and sign a **web server certificate** (EKU = `serverAuth`) using a YubiKey PIV.
* **Usage**:

```bash
./mk-piv-webcert.sh <CN> [IP] [BITS]
```

* **Parameters**:

  * `CN` (required) — Common Name and output folder name.
  * `IP` (optional) — IP address for Subject Alternative Name (SAN).
  * `BITS` (optional) — RSA key size (default 2048).
* **Behavior**:

  * Generates an RSA key + CSR locally.
  * Signs CSR with YubiKey PIV CA key (slot 9c via PKCS#11).
  * Generates output files in `<CN>/`:

    * `CN.crt` — certificate
    * `CN.fullchain.pem` — CRT + CA chain
    * `CN.p12` — PKCS#12 bundle
    * `CN.zip` — zipped folder
  * Generates a **32-character password** for key protection and PFX export.
  * Optionally prints the decrypted private key if `PRINT_KEY=1`.
  * Cleans up private key and temporary files.

---

### 2. `mk-piv-client-cert.sh`

* **Purpose**: Generate and sign a **TLS client certificate** (EKU = `clientAuth`) using YubiKey PIV.
* **Usage**:

```bash
./mk-piv-client-cert.sh <CN> [EMAIL] [BITS]
```

* **Parameters**:

  * `CN` (required) — Common Name and output folder name.
  * `EMAIL` (optional) — Email for SAN (`rfc822Name`) and DN (`emailAddress`).
  * `BITS` (optional) — RSA key size (default 2048).
* **Behavior**:

  * Generates an RSA key + CSR locally.
  * Signs CSR with YubiKey PIV CA key.
  * Generates output files in `<CN>/` (same as web script).
  * Uses a 32-character password for private key and PFX export.
  * Optionally prints the decrypted private key if needed.
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

* **Security Notes**:

  * Private key is generated encrypted with a random password.
  * Password is used for PFX export and then unset.
  * Temporary and sensitive files are removed automatically.
  * Decrypted private key is only printed if explicitly requested.

* **SAN and EKU**:

  * Web script: DNS CN + optional IP SAN, EKU = `serverAuth`.
  * Client script: CN + optional email SAN, EKU = `clientAuth`.

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

* The scripts **require a YubiKey PIV with the CA key** in slot 9c.
* The scripts **automatically manage serial files** for certificates.
* Generated passwords are **random and not stored**; if you need the private key later, you must print it during generation.
* The CA private key **never leaves the YubiKey**; all signing is done via PKCS#11.

---

This README covers both scripts’ usage, configuration, outputs, and security considerations.
