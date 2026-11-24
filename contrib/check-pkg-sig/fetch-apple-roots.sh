#!/bin/sh
# Download Apple's root CA certificates (over HTTPS, from www.apple.com)
# and bundle them into apple-roots.pem for use with pkg_sig_check.py.
set -eu

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -sfL -o "$tmp/AppleIncRootCertificate.cer" \
    https://www.apple.com/appleca/AppleIncRootCertificate.cer
for cert in AppleRootCA-G2 AppleRootCA-G3; do
    curl -sfL -o "$tmp/$cert.cer" \
        "https://www.apple.com/certificateauthority/$cert.cer"
done

: > apple-roots.pem
for cert in "$tmp"/*.cer; do
    openssl x509 -inform DER -in "$cert" >> apple-roots.pem
done

echo "wrote $(pwd)/apple-roots.pem"
