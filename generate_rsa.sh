#!/bin/zsh
openssl genrsa -out dev_key.pem 2048
openssl rsa -in dev_key.pem -outform PEM -pubout -out dev.pub
openssl rsa -in dev_key.pem -outform PEM -out dev
rm -rf dev_key.pem
