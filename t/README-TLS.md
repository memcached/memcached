# Certificates creation process

The following certificates are used in tests, that assume expiration date
to always be in the future, so instead of a normal cert validity of 1-5 years.
we use 500 years here.

## Create certificate authority key and certificate
```
$ openssl genrsa -out cakey.pem 2048
$ openssl req -x509 -new -nodes -key cakey.pem -sha256 -days 182500 -out cacert.pem \
    -subj "/CN=Test Root Certificate Authority/ST=CA/C=US/emailAddress=root@test.com/O=Test/OU=Test Department"
```
## Create server key and certificate
```
$ openssl genrsa -out server_key.pem 2048
$ openssl req -new -sha256 -key server_key.pem \
    -subj "/C=US/ST=CA/O=Test/OU=Subunit of Test Organization/CN=test.com/emailAddress=root@test.com" \
    -addext "subjectAltName=DNS:test.com,DNS:alt.test.com" \
    -out server_crt.csr
$ openssl x509 -req -in server_crt.csr -CA cacert.pem -CAkey cakey.pem \
    -extfile <(printf "subjectAltName=DNS:test.com,DNS:alt.test.com") \
    -CAcreateserial -out server_crt.pem -days 182500 -sha256 -text
```
## Create client key and certificate
```
$ openssl genrsa -out client_key.pem 2048
$ openssl req -new -sha256 -key client_key.pem \
    -subj "/C=US/ST=CA/O=Test Client/OU=Subunit of Test Organization/CN=client.test.com/emailAddress=root@client.test.com" \
    -addext "subjectAltName=DNS:client.test.com,DNS:alt.client.test.com" \
    -out client_crt.csr
$ openssl x509 -req -in client_crt.csr -CA cacert.pem -CAkey cakey.pem \
    -extfile <(printf "subjectAltName=DNS:client.test.com,DNS:alt.client.test.com") \
    -CAcreateserial -out client_crt.pem -days 182500 -sha256 -text
```

**NOTES**: *.csr files are certificate signing requests which are needed in order to sign certificates with signing authority.
-CAcreateserial option creates one file which we do not need but openssl does. You can delete it after you are done.
