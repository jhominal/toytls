#!/usr/bin/env sh
parent=$1
target=$2

if [ ! -e "$target/private.key" ]; then
  openssl genrsa -out "$target/private.key" 2048
fi

openssl req -new -key "$target/private.key" -out "$target/request.csr" -config "$target/request.cnf"

if [ "$parent" = "self" ]; then
  # Self-signed certificate
  openssl x509 -in "$target/request.csr" -req -addtrust clientAuth -trustout -signkey "$target/private.key" -extfile "$target/request.cnf" -out "$target/certificate.crt"
else
  # Certificate signed by CA certificate
  openssl x509 -in "$target/request.csr" -req -CA "$parent/certificate.crt" -CAkey "$parent/private.key" -CAcreateserial -extfile "$target/request.cnf" -out "$target/certificate.crt"
fi
