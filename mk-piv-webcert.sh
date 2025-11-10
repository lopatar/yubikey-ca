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
  RSA_BITS, CA_CERT, DAYS, CA_KEY_URI, OUTDIR, PKCS11_MODULE_PATH

Behavior:
  • Generates RSA key + CSR
  • Signs CSR using YubiKey PIV slot 9c (via PKCS#11)
  • Outputs certs to <CN>/:
        CN.crt, CN.fullchain.pem, CN.pfx, CN.zip
  • Prints the certificate private key (not saved)       
  • Prints a random 16-hex PFX password (not saved)
  • Deletes private key and temp files
  • Displays certificate info at the end

Examples:
  ./mk-piv-webcert.sh ap.wifi.lopatar.local
  ./mk-piv-webcert.sh ap.wifi.lopatar.local 10.69.69.2 4096
EOF
}

# --- Args / defaults ---
CN="${1:-}"
[[ -z "${CN}" || "${CN}" == "-h" || "${CN}" == "--help" ]] && { print_usage; exit 2; }
IP="${2:-}"
RSA_BITS="${RSA_BITS:-${3:-2048}}"
[[ "$RSA_BITS" =~ ^[0-9]+$ ]] || { echo "Invalid RSA key size"; exit 2; }

# --- Config (override via env) ---
CA_CERT="${CA_CERT:-LopatarCA.crt}"
DAYS="${DAYS:-1825}"
CA_KEY_URI="${CA_KEY_URI:-pkcs11:object=Private%20key%20for%20Digital%20Signature;type=private}"
OUTDIR="${OUTDIR:-$CN}"

# --- Locate libykcs11.so if not set ---
if [[ -z "${PKCS11_MODULE_PATH:-}" || ! -e "${PKCS11_MODULE_PATH:-/dev/null}" ]]; then
  for p in /usr/lib/*/libykcs11.so /usr/local/lib/libykcs11.so /lib/*/libykcs11.so; do
    [[ -e "$p" ]] && PKCS11_MODULE_PATH="$p" && export PKCS11_MODULE_PATH && break
  done
fi
: "${PKCS11_MODULE_PATH:?Set PKCS11_MODULE_PATH to libykcs11.so}"

# --- Sanity ---
command -v openssl >/dev/null || { echo "openssl not found"; exit 3; }
command -v zip >/dev/null     || { echo "zip not found"; exit 3; }
[[ -f "$CA_CERT" ]] || { echo "CA cert '$CA_CERT' not found"; exit 4; }

# --- Paths ---
mkdir -p "$OUTDIR"
BASE="$CN"
KEY="$OUTDIR/$BASE.key"
CSR="$OUTDIR/$BASE.csr"
CRT="$OUTDIR/$BASE.crt"
EXT="$OUTDIR/$BASE.ext"
CSR_CNF="$OUTDIR/$BASE.csr.cnf"
FULLCHAIN="$OUTDIR/$BASE.fullchain.pem"
PFX="$OUTDIR/$BASE.pfx"
ZIP="$OUTDIR/$BASE.zip"
SRL="${CA_CERT%.*}.srl"

secure_rm() { command -v shred >/dev/null && shred -u -- "$@" || rm -f -- "$@"; }

# --- SANs ---
SAN_DNS="DNS.1 = $CN"
SAN_IP=""; [[ -n "$IP" ]] && SAN_IP=$'\n'"IP.1  = $IP"

# --- Signing extensions (AKID here) ---
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

# --- CSR config ---
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

# --- Generate key + CSR ---
openssl req -new -newkey "rsa:${RSA_BITS}" -nodes \
  -keyout "$KEY" -out "$CSR" -config "$CSR_CNF"

# --- Sign with YubiKey (pkcs11 engine) ---
openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkeyform engine -engine pkcs11 -CAkey "$CA_KEY_URI" \
  -CAcreateserial -CAserial "$SRL" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT" -extensions v3_cert \
  -out "$CRT"

# --- Full chain ---
cat "$CRT" "$CA_CERT" > "$FULLCHAIN"

# --- Export PFX with random 16-char password ---
PFX_PASS="$(openssl rand -hex 8)"
openssl pkcs12 -export \
  -inkey "$KEY" -in "$CRT" -certfile "$CA_CERT" \
  -name "$CN" -out "$PFX" \
  -passout "pass:$PFX_PASS"

echo ""
cat "$KEY"
echo ""

echo ""
echo "> Certificate generated successfully"
echo "> CN: $CN"
echo "> RSA bits: $RSA_BITS"
echo "> PFX password (printed once): $PFX_PASS"
echo ""

unset PFX_PASS

# --- Cleanup sensitive files ---
secure_rm "$KEY"
rm -f "$CSR" "$EXT" "$CSR_CNF"

# --- Zip folder contents ---
( cd "$OUTDIR" && rm -f "$BASE.zip" && zip -r "$BASE.zip" . -x "$BASE.zip" >/dev/null )

echo ""
echo "Files saved in: $OUTDIR/"
printf '  %s\n  %s\n  %s\n  %s\n' "$CRT" "$FULLCHAIN" "$PFX" "$ZIP"
