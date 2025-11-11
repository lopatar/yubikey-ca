#!/usr/bin/env bash
# mk-piv-client-cert.sh — generate & sign TLS client (clientAuth) certificate using YubiKey PIV (slot 9c)
# Usage: ./mk-piv-client-cert.sh <CN> [EMAIL] [BITS]
set -euo pipefail
umask 077

print_usage() {
  cat <<'EOF'
Usage:
  mk-piv-client-cert.sh <CN> [EMAIL] [BITS]

Parameters:
  CN     (required)  Common Name (also folder name)
  EMAIL  (optional)  Email to include in SAN (rfc822Name) and DN emailAddress
  BITS   (optional)  RSA key size, default 2048

Environment overrides:
  RSA_BITS, CA_CERT, DAYS, CA_KEY_URI, OUTDIR, PKCS11_MODULE_PATH

Behavior:
  • Generates encrypted RSA key + CSR
  • Signs CSR using YubiKey PIV slot 9c (via PKCS#11)
  • Extended Key Usage: clientAuth
  • Outputs certs to <CN>/:
        CN.crt, CN.fullchain.pem, CN.pfx, CN.zip
  • Prints a random 16-char P12 bundle password (not saved)
  • Deletes private key and temp files
  • Displays certificate info at the end

Examples:
  ./mk-piv-client-cert.sh alice
  ./mk-piv-client-cert.sh alice alice@example.com 4096
EOF
}

# Args / defaults
CN="${1:-}"
[[ -z "${CN}" || "${CN}" == "-h" || "${CN}" == "--help" ]] && { print_usage; exit 2; }
EMAIL="${2:-}"
RSA_BITS="${RSA_BITS:-${3:-2048}}"
[[ $RSA_BITS =~ ^[0-9]+$ ]] || { echo "Invalid RSA key size"; exit 2; }

# Config (override via env)
CA_CERT="${CA_CERT:-LopatarCA.crt}"
DAYS="${DAYS:-1825}"
CA_KEY_URI="${CA_KEY_URI:-pkcs11:object=Private%20key%20for%20Digital%20Signature;type=private}"
OUTDIR="${OUTDIR:-$CN}"

# Locate libykcs11.so if not set
if [[ -z "${PKCS11_MODULE_PATH:-}" || ! -e "${PKCS11_MODULE_PATH}" ]]; then
  for p in /usr/lib/*/libykcs11.so /usr/local/lib/libykcs11.so /lib/*/libykcs11.so; do
    [[ -e "$p" ]] && PKCS11_MODULE_PATH="$p" && export PKCS11_MODULE_PATH && break
  done
fi
if [[ -z "${PKCS11_MODULE_PATH:-}" || ! -e "${PKCS11_MODULE_PATH}" ]]; then
  echo "libykcs11.so not found. Set PKCS11_MODULE_PATH to the path of libykcs11.so"; exit 3
fi

# Check for prerequisites
command -v openssl >/dev/null || { echo "openssl not found"; exit 3; }
command -v zip >/dev/null     || { echo "zip not found"; exit 3; }
[[ -f "$CA_CERT" ]] || { echo "CA cert '$CA_CERT' not found"; exit 4; }

# Paths
mkdir -p "$OUTDIR"
BASE="$CN"
KEY="$OUTDIR/$BASE.key"
CSR="$OUTDIR/$BASE.csr"
CRT="$OUTDIR/$BASE.crt"
EXT="$OUTDIR/$BASE.ext"
CSR_CNF="$OUTDIR/$BASE.csr.cnf"
FULLCHAIN="$OUTDIR/$BASE.fullchain.pem"
PFX="$OUTDIR/$BASE.p12"
ZIP="$OUTDIR/$BASE.zip"
SRL="${CA_CERT%.*}.srl"

# use shred to dispose of the private key, fallback to rm
secure_rm() {
    if command -v shred >/dev/null; then
        shred -u -- "$@"
    else
        rm -f -- "$@"
    fi
}

# SAN/email
DN_EMAIL=""
SAN_EMAIL=""
if [[ -n "$EMAIL" ]]; then
  DN_EMAIL=$'\n'"emailAddress = $EMAIL"
  SAN_EMAIL=$'\n'"email = $EMAIL"
fi

# Fallback SAN if no email provided (some stacks expect SAN present)
SAN_DNS_FALLBACK=""
if [[ -z "$SAN_EMAIL" ]]; then
  SAN_DNS_FALLBACK=$'\n'"DNS.1 = $CN"
fi

# Signing extensions, key usage
cat > "$EXT" <<EOF
[v3_cert]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt

[alt]
# rfc822Name if EMAIL provided; otherwise include CN as a DNS SAN fallback
$(printf '%s' "$SAN_EMAIL$SAN_DNS_FALLBACK")
EOF

# CSR config
cat > "$CSR_CNF" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = $CN$(printf '%s' "$DN_EMAIL")

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt

[alt]
$(printf '%s' "$SAN_EMAIL$SAN_DNS_FALLBACK")
EOF

# Generate random 32-char password, used for encrypting the private key on disk
export KEY_PASS
KEY_PASS=$(openssl rand -hex 16)

# --- Generate key + CSR ---
openssl req -new -newkey "rsa:${RSA_BITS}" \
    -keyout "$KEY" -out "$CSR" -config "$CSR_CNF" \
    -aes256 -passout "env:$KEY_PASS"

# Ensure a serial file exists at our chosen path
if [[ ! -f "$SRL" ]]; then
  echo '01' > "$SRL"
fi

# Sign with YubiKey (pkcs11 engine)
openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkeyform engine -engine pkcs11 -CAkey "$CA_KEY_URI" \
  -CAserial "$SRL" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT" -extensions v3_cert \
  -out "$CRT"

# Create fullchain file
cat "$CRT" "$CA_CERT" > "$FULLCHAIN"

# Export PFX/P12 with a random 16-char password (Windows has issues importing with longer passwords)
export PFX_PASS
PFX_PASS="$(openssl rand -hex 8)"
openssl pkcs12 -export \
  -inkey "$KEY" -in "$CRT" -certfile "$CA_CERT" \
  -name "$CN" -out "$PFX" \
  -passin "env:$KEY_PASS" -passout "env:$PFX_PASS" \
  -keypbe AES-256-CBC -certpbe AES-256-CBC

unset KEY_PASS

echo ""
echo "> Client certificate generated successfully"
echo "> CN: $CN"
[[ -n "$EMAIL" ]] && echo "> Email (SAN/DN): $EMAIL"
echo "> RSA bits: $RSA_BITS"
echo "> EKU: clientAuth"
echo "> P12 password (printed once): $PFX_PASS" > /dev/tty # sensitive, use same logic as for private key in web server script
echo ""

unset PFX_PASS

# Cleanup sensitive files
secure_rm "$KEY"
rm -f "$CSR" "$EXT" "$CSR_CNF"

# Zip folder contents 
( cd "$OUTDIR" && rm -f "$BASE.zip" && zip -r "$BASE.zip" . -x "$BASE.zip" >/dev/null )

echo ""
echo "Files saved in: $OUTDIR/"
printf '  %s\n  %s\n  %s\n  %s\n' "$CRT" "$FULLCHAIN" "$PFX" "$ZIP"
