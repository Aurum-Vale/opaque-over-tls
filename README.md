# OPAQUE over TLS PoC

This project acts as a proof of concept of using OPAQUE over TLS.

## Installation

Certificates must first be generated for the server and the certificate authority. The `openssl` folder includes the `generate.sh` script to generate the certificates, according to the configuration files also present in the folder.

It is possible to change the public key scheme used for TLS by uncommenting specific lines in the script.

Otherwise, the project fully relies on `cargo`, the Rust utility program for compilation and dependency management.

## Usage

Three programes are provided in the project. The client and server work together, the server must be launched first. It will generate a valid `credentials` folder if there isn't already one. It contains the server setup configuration for OPAQUE, and the registered clients' sealed credentials.

IMPORTANT: if the `OpaqueCipherSuite` struct in `lib.rs` is changed (to use a different KSF for example), the server setup will no longer be valid and the whole `credentials` folder will be regenerated.

Once connected, the client can register any number of users, and login as any of them. Once logged in, a user can send any text message, that will be echoed in reverse by the server; those messages are encrypted by the OPAQUE session key.

The benchmark program acts separately as both a client and a server, without a TCP stack in the middle, to measure the size of the messages exchanged and the time it took to process messages.
