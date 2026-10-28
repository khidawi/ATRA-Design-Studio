#!/bin/sh
# Makes the certificates that encrypt the connection between the API and the database (run once by the "certs" service in docker-compose.prod.yml, and again at every
# start: it does nothing while the certificate has more than 30 days left).
#
#   /tls  the database's private key and certificate (mounted into the database container only; the key belongs to the postgres user, mode 600)
#   /ca   the certificate authority's public certificate, which the API uses to check it is talking to the real database (mounted into the API read-only; no key in it)
#
# The authority's private key is used once to sign the server certificate and then thrown away: nothing can mint another certificate for this database afterwards.
set -eu
TLS=/tls
CA=/ca
mkdir -p "$TLS" "$CA"
if [ -f "$TLS/server.crt" ] && [ -f "$TLS/server.key" ] && [ -f "$CA/ca.crt" ] && openssl x509 -checkend 2592000 -noout -in "$TLS/server.crt" >/dev/null 2>&1; then
  echo "The database certificate is valid for more than 30 days: nothing to do."
  exit 0
fi
W=$(mktemp -d)
cd "$W"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 1825 -subj "/CN=ASTRA database CA" -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=db" -out server.csr
printf 'subjectAltName=DNS:db,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -sha256 -extfile ext.cnf -out server.crt
cp server.crt server.key "$TLS/"
cp ca.crt "$CA/ca.crt"
chown 70:70 "$TLS/server.key" "$TLS/server.crt"      # uid 70 is the postgres user in the official postgres image
chmod 600 "$TLS/server.key"
chmod 644 "$TLS/server.crt" "$CA/ca.crt"
rm -rf "$W"
echo "Made a new database certificate (valid 825 days) and the authority certificate the API checks it against. Restart the API to pick up the new authority."
