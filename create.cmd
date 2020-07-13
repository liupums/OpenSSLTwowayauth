@echo off
RMDIR /Q/S certs
md certs
REM To skip the following Python commands, put "REM" before them:
REM Create a Certificate Authority private key (this is your most important key):
openssl req -new -newkey rsa:1024 -nodes -out certs/ca.csr -keyout certs/ca.key -subj "/C=US/ST=WA/L=Provo/O=FakeCA/CN=FakeCA.com"

REM Create your CA self-signed certificate:
openssl x509 -trustout -signkey certs/ca.key -days 365 -req -in certs/ca.csr -out certs/ca.cer

REM Issue a client certificate by first generating the key, then request (or use one provided by external system) 
REM then sign the certificate using private key of your CA:

openssl genrsa -out certs/client.key 1024
openssl req -new -key certs/client.key -out certs/client.csr -subj "/C=US/ST=WA/L=Provo/O=FakeClient/CN=FakeClient.com"
openssl x509 -req -days 365 -in certs/client.csr -CA certs/ca.cer -CAkey certs/ca.key -set_serial 01 -out certs/client.cer

openssl genrsa -out certs/server.key 1024
openssl req -new -key certs/server.key -out certs/server.csr -subj "/C=US/ST=WA/L=Provo/O=FakeServer/CN=FakeServer.com"
openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca.cer -CAkey certs/ca.key -set_serial 01 -out certs/server.cer

type "certs\server.cer" "certs\ca.cer" > certs\chain.cer
REM use "certlm" to install ca.cer into trusted root