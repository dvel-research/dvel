#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: gen_tls_selfsigned.sh <output-dir> <host> [name]" >&2
  exit 2
fi

out_dir="$1"
host="$2"
name="${3:-node}"

mkdir -p "$out_dir"
key_path="$out_dir/${name}.key"
crt_path="$out_dir/${name}.crt"

if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$host" == *:* ]]; then
  san="IP:$host"
else
  san="DNS:$host"
fi

tmp_conf="$(mktemp)"
cat > "$tmp_conf" <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=$host

[v3_req]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=$san
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout "$key_path" \
  -out "$crt_path" \
  -sha256 \
  -config "$tmp_conf" \
  -extensions v3_req

rm -f "$tmp_conf"

echo "Wrote $key_path"
echo "Wrote $crt_path"
echo "Paste cert hex into genesis:"
echo "  python3 scripts/cert_hex.py $crt_path"
