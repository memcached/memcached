# Certificates creation process

## Create certificate authority key and certificate
```
$ openssl genrsa -out cakey.pem 2048
$ openssl req -x509 -new -nodes -key cakey.pem -sha256 -days 1825 -out cacert.pem \
-subj "/CN=Test Root Certificate Authority/ST=CA/C=US/emailAddress=root@test.com/O=Test/OU=Test Department"
```
## Create server key and certificate
```
$ openssl genrsa -out server_key.pem 2048
$ openssl req -new -sha256 -key server_key.pem -subj \
"/C=US/ST=CA/O=Test/OU=Subunit of Test Organization/CN=test.com/emailAddress=root@test.com" \
-out server_crt.csr
$ openssl x509 -req -in server_crt.csr -CA cacert.pem -CAkey cakey.pem \
-CAcreateserial -out server_cert.pem -days 1825 -sha256
```
## Create client key and certificate
```
$ openssl genrsa -out client_key.pem 2048
$ openssl req -new -sha256 -key client_key.pem -subj \
"/C=US/ST=CA/O=Test Client/OU=Subunit of Test Organization/CN=client.test.com/emailAddress=root@client.test.com" \
-out client_crt.csr
$ openssl x509 -req -in client_crt.csr -CA cacert.pem -CAkey cakey.pem \
-CAcreateserial -out client_cert.pem -days 1825 -sha256
```

**NOTES**: *.csr files are certificate signing requests which are needed in order to sign certificates with signing authority.
-CAcreateserial option creates one file which we do not need but openssl does. You can delete it after you are done.
