#!/usr/bin/env sh
./generate_rsa_cert.sh self 0-root
./generate_rsa_cert.sh 0-root 1-intermediate
./generate_rsa_cert.sh 1-intermediate 2-leaf
