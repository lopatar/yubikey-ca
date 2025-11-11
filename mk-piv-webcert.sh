#!/usr/bin/env bash
# mk-piv-webcert.sh — generate & sign web server certificate using YubiKey PIV (slot 9c)
# Usage: ./mk-piv-webcert.sh <CN> [IP] [BITS]
set -euo pipefail
umask 077

print_usage() {
  cat <<'EOF'
Usage:
  mk-piv-webcert.sh <CN> [IP] [BITS]

Parameters:
  CN    (required)  Common Name (also folder name)
  IP    (optional)  IP address to include in SAN
  BITS  (optional)  RSA key size, default 2048

Environment overrides:
  RSA_BITS, CA_CERT, DAYS, CA_KEY_URI, OUTDIR, PKCS11_MODULE_PATH, PRINT_KEY

Behavior:
  • Generates encrypted RSA key + CSR
  • Signs CSR using YubiKey PIV slot 9c (via PKCS#11)
  • Outputs certs to <CN>/:
        CN.crt, CN.fullchain.pem, CN.pfx, CN.zip
  • Optionally prints the certificate private key (not saved)     
  • Prints a random 16-char P12 bundle password (not saved)
  • Deletes private key and temp files
  • Displays certificate info at the end

Examples:
  ./mk-piv-webcert.sh ap.wifi.lopatar.local
  ./mk-piv-webcert.sh ap.wifi.lopatar.local 10.69.69.2 4096
EOF
}

# Args / defaults
CN="${1:-}"
[[ -z "${CN}" || "${CN}" == "-h" || "${CN}" == "--help" ]] && { print_usage; exit 2; }
IP="${2:-}"
RSA_BITS="${RSA_BITS:-${3:-2048}}"
[[ "$RSA_BITS" =~ ^[0-9]+$ ]] || { echo "Invalid RSA key size"; exit 2; }

# Config (override via env)
CA_CERT="${CA_CERT:-LopatarCA.crt}"
DAYS="${DAYS:-1825}"
CA_KEY_URI="${CA_KEY_URI:-pkcs11:object=Private%20key%20for%20Digital%20Signature;type=private}"
OUTDIR="${OUTDIR:-$CN}"
# If 1/true, print private key to console /dev/tty
PRINT_KEY="${PRINT_KEY:-0}"
# Locate libykcs11.so if not set
if [[ -z "${PKCS11_MODULE_PATH:-}" || ! -e "${PKCS11_MODULE_PATH:-/dev/null}" ]]; then
  for p in /usr/lib/*/libykcs11.so /usr/local/lib/libykcs11.so /lib/*/libykcs11.so; do
    [[ -e "$p" ]] && PKCS11_MODULE_PATH="$p" && export PKCS11_MODULE_PATH && break
  done
fi
: "${PKCS11_MODULE_PATH:?Set PKCS11_MODULE_PATH to libykcs11.so}"

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

# SAN
SAN_DNS="DNS.1 = $CN"
SAN_IP=""; [[ -n "$IP" ]] && SAN_IP=$'\n'"IP.1  = $IP"

# Signing extensions, key usage
cat > "$EXT" <<EOF
[v3_cert]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt

[alt]
$SAN_DNS$SAN_IP
EOF

# CSR config
cat > "$CSR_CNF" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req
[dn]
CN = $CN
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
$SAN_DNS$SAN_IP
EOF

# Generate random 32-char password, used for encrypting the private key on disk
export KEY_PASS
KEY_PASS=$(openssl rand -hex 16)

# Generate key + CSR
openssl req -new -newkey "rsa:${RSA_BITS}" \
    -keyout "$KEY" -out "$CSR" -config "$CSR_CNF" \
    -passout "env:$KEY_PASS"

# Sign with YubiKey (pkcs11 engine)
openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkeyform engine -engine pkcs11 -CAkey "$CA_KEY_URI" \
  -CAcreateserial -CAserial "$SRL" \
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
  -keypbe AES-256-CBC -certpbe AES-256-CBC # Use AES-256-CBC for the private key & certificate bags

# Optionally print private key
if [[ "$PRINT_KEY" == 1 || "$PRINT_KEY" == "true" ]]; then
  echo ""
  # print directly to the terminal descriptor (bypasses shell redirection)
  openssl rsa -in "$KEY" -passin "env:$KEY_PASS" > /dev/tty
  echo ""
fi

unset KEY_PASS

echo ""
echo "> WWW server cert generated successfully"
echo "> CN: $CN"
[[ -n "$IP" ]] && echo "> IP (SAN): $IP"
echo "> RSA bits: $RSA_BITS"
echo "> EKU: serverAuth"
echo "> P12 password (printed once): $PFX_PASS" > /dev/tty # sensitive, use same logic as for private key
echo ""

unset PFX_PASS

# Cleanup sensitive files
secure_rm "$KEY"
rm -f "$CSR" "$EXT" "$CSR_CNF"

# Zip folder contents
( cd "$OUTDIR" && rm -f "$BASE.zip" && zip -r "$BASE.zip" . -x "$BASE.zip" >/dev/null )

echo ""
echo "Files saved in: $OUTDIR/"
chmod 600 "$CRT" "$FULLCHAIN" "$PFX" "$ZIP"
printf '  %s\n  %s\n  %s\n  %s\n' "$CRT" "$FULLCHAIN" "$PFX" "$ZIP"