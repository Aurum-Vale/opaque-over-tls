#!/bin/bash -x

# Certificate authority (root)
openssl req -x509 \
            -sha256 -days 356 \
            -nodes \
            -newkey rsa:2048 \
            -subj "/CN=ca.localhost/C=FR/L=Limoges" \
            -keyout rootCA.key -out rootCA.crt


# Generate the server private key
# RSA 2048 bits
# openssl genrsa -out server.key 2048
# RSA 4096 bits
# openssl genrsa -out server.key 4096
# ECDHE, Ed25519 (256 bits)
# openssl genpkey -out server.key -algorithm ed25519
# ECDHE, Curve P-256 (256 bits)
openssl genpkey -out server.key -algorithm EC -pkeyopt ec_paramgen_curve:P-256

# Create the certificate signature request (CSR)
openssl req -new -key server.key -out server.csr -config csr.conf

# Self-sign the CSR with the CA
openssl x509 -req \
    -in server.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server.crt \
    -days 365 \
    -sha256 -extfile cert.conf