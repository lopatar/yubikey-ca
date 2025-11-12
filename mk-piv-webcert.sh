#!/usr/bin/env bash
# mk-piv-webcert-ecc.sh — generate & sign web server certificate using YubiKey PIV (slot 9c) with ECC
# Usage: ./mk-piv-webcert-ecc.sh <CN> [IP] [CURVE]
set -euo pipefail
set +o history
umask 077

print()
{
  echo "$1" > /dev/tty
}

print_usage() {
  cat <<'EOF'
Usage:
  mk-piv-webcert-ecc.sh <CN> [IP] [CURVE]

Parameters:
  CN    (required)  Common Name (also folder name)
  IP    (optional)  IP address to include in SAN
  CURVE (optional)  ECC curve name, default secp384r1

Environment overrides:
  CA_CERT, DAYS, CA_KEY_URI, OUTDIR, PKCS11_MODULE_PATH, PRINT_KEY, ECC_CURVE

Behavior:
  • Generates encrypted ECC key + CSR
  • Signs CSR using YubiKey PIV slot 9c (via PKCS#11)
  • Outputs certs to <CN>/:
        CN.crt, CN.fullchain.pem, CN.p12, CN.zip
  • Optionally prints the certificate private key (not saved)
  • Prints a random 16-char P12 bundle password (not saved)
  • Deletes private key and temp files
  • Displays certificate info at the end
EOF
}

# Args / defaults
CN="${1:-}"
[[ -z "${CN}" || "${CN}" == "-h" || "${CN}" == "--help" ]] && { print_usage; exit 2; }
IP="${2:-}"
ECC_CURVE="${ECC_CURVE:-${3:-secp384r1}}"

# Config (override via env)
CA_CERT="${CA_CERT:-LopatarCA.crt}"
DAYS="${DAYS:-1825}"
CA_KEY_URI="${CA_KEY_URI:-pkcs11:object=Private%20key%20for%20Digital%20Signature;type=private}"
OUTDIR="${OUTDIR:-$CN}"
PRINT_KEY="${PRINT_KEY:-0}"

# Locate libykcs11.so if not set
if [[ -z "${PKCS11_MODULE_PATH:-}" || ! -e "${PKCS11_MODULE_PATH:-/dev/null}" ]]; then
  for p in /usr/lib/*/libykcs11.so /usr/local/lib/libykcs11.so /lib/*/libykcs11.so; do
    [[ -e "$p" ]] && PKCS11_MODULE_PATH="$p" && export PKCS11_MODULE_PATH && break
  done
fi
: "${PKCS11_MODULE_PATH:?Set PKCS11_MODULE_PATH to libykcs11.so}"

# Check for prerequisites
command -v openssl >/dev/null || { print "openssl not found"; exit 3; }
command -v zip >/dev/null     || { print "zip not found"; exit 3; }
[[ -f "$CA_CERT" ]] || { print "CA cert '$CA_CERT' not found"; exit 4; }

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

secure_rm() {
    if command -v shred >/dev/null; then
        shred -f -u -z -n 15 -- "$@"
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
keyUsage = critical, digitalSignature
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
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
$SAN_DNS$SAN_IP
EOF

#clear variables as soon as they are not used
unset SAN_DNS
unset SAN_IP

# Generate random 32-char password
export KEY_PASS
KEY_PASS=$(openssl rand -hex 16)

# Generate ECC key + CSR
openssl ecparam -name "$ECC_CURVE" -genkey -noout | openssl ec -aes256 -out "$KEY" -passout "env:KEY_PASS"
openssl req -new -key "$KEY" -out "$CSR" -config "$CSR_CNF" -passin "env:KEY_PASS"

# Sign with YubiKey (pkcs11 engine) with appropriate digest based on curve
DIGEST=""
case "$ECC_CURVE" in
  secp256r1) DIGEST="sha256" ;;
  secp384r1) DIGEST="sha384" ;;
  *) DIGEST="sha256" ;;
esac

openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkeyform engine -engine pkcs11 -CAkey "$CA_KEY_URI" \
  -CAcreateserial -CAserial "$SRL" \
  -days "$DAYS" -$DIGEST \
  -extfile "$EXT" -extensions v3_cert \
  -out "$CRT"

# Create fullchain file
cat "$CRT" "$CA_CERT" > "$FULLCHAIN"

# Export PFX/P12
export PFX_PASS
PFX_PASS="$(openssl rand -hex 8)"
openssl pkcs12 -export \
  -inkey "$KEY" -in "$CRT" -certfile "$CA_CERT" \
  -name "$CN" -out "$PFX" \
  -passin "env:KEY_PASS" -passout "env:PFX_PASS" \
  -keypbe AES-256-CBC -certpbe AES-256-CBC

# Optionally print private key
if [[ "$PRINT_KEY" == 1 || "$PRINT_KEY" == "true" ]]; then
  print ""
  openssl ec -in "$KEY" -passin "env:KEY_PASS" > /dev/tty
  print ""
fi

unset KEY_PASS

print ""
print "> WWW server cert generated successfully"
print "> CN: $CN"
[[ -n "$IP" ]] && print "> IP (SAN): $IP"
print "> ECC curve: $ECC_CURVE"
print "> EKU: serverAuth"
print "> P12 password (printed once): $PFX_PASS" > /dev/tty

print ""
unset PFX_PASS

# Cleanup sensitive files
secure_rm "$KEY"
secure_rm "$CSR" "$EXT" "$CSR_CNF"

# Zip folder contents
( cd "$OUTDIR" && rm -f "$BASE.zip" && zip -r "$BASE.zip" . -x "$BASE.zip" >/dev/null )

print ""
print "Files saved in: $OUTDIR/"
printf '  %s\n  %s\n  %s\n  %s\n' "$CRT" "$FULLCHAIN" "$PFX" "$ZIP" > /dev/tty
set -o history #enable history
history -c #clear current shell history
