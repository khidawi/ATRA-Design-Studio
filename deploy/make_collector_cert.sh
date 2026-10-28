#!/bin/sh
# Makes a client certificate for one application that sends data to ASTRA (see docker-compose.mtls.yml).
#
#   ./make_collector_cert.sh checkout-service [days]
#
# Writes, in this folder: client-ca.pem (the authority's public certificate, which Caddy checks against; made the first time), client-ca.key (the authority's private key: keep it
# offline, apart from the server), and NAME.crt and NAME.key for the application (give it these two; the key is secret).
set -eu
export MSYS_NO_PATHCONV=1          # Git Bash on Windows would otherwise rewrite the /CN=... subject as a file path
cd "$(dirname "$0")"
NAME="${1:?give the application a name, for example checkout-service}"
DAYS="${2:-365}"
case "$NAME" in *[!A-Za-z0-9._-]*) echo "Use letters, digits, dot, dash and underscore only."; exit 2;; esac
umask 077
if [ ! -f client-ca.key ] || [ ! -f client-ca.pem ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out client-ca.key
  openssl req -x509 -new -key client-ca.key -sha256 -days 3650 -subj "/CN=ASTRA collector CA" -out client-ca.pem
  echo "Made the collector authority: client-ca.pem (public) and client-ca.key (private: keep it offline)."
fi
openssl ecparam -name prime256v1 -genkey -noout -out "$NAME.key"
openssl req -new -key "$NAME.key" -subj "/CN=$NAME" -out "$NAME.csr"
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' > "$NAME.ext"
openssl x509 -req -in "$NAME.csr" -CA client-ca.pem -CAkey client-ca.key -CAcreateserial -days "$DAYS" -sha256 -extfile "$NAME.ext" -out "$NAME.crt"
rm -f "$NAME.csr" "$NAME.ext" client-ca.srl
chmod 644 client-ca.pem "$NAME.crt"
echo "Made $NAME.crt and $NAME.key (valid $DAYS days). Give the application these two files; set ASTRA_CLIENT_CERT and ASTRA_CLIENT_KEY to their paths."
