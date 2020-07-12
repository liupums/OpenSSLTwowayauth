# OpenSSLTwowayauth
Demo two way auth using SSL
## Server
1. Web Server uses cheroot in cherrypy https://github.com/cherrypy/cheroot
2. SSL uses PyOpenssl
## Client
1. Client uses socket
2. SSL uses PyOpenssl
## Testing certs
1. Use OpenSSL
2. FakeCA --> FakeServer

   FakeCA --> FakeClient
## Steps
1. Testing on windows 
2. Run "create.cmd" to create testing certs
3. In one command window, start server by "python server.py"
4. In another command window, start client by "python client.py"

## Running Log
1. create testing certs
```
    E:\pop\repo\OpenSSLTwowayauth>create.cmd
    Generating a 1024 bit RSA private key
    ......................................................................++++++
    ...++++++
    writing new private key to 'certs/ca.key'
    -----
    Signature ok
    subject=/C=US/ST=WA/L=Provo/O=FakeCA/CN=FakeCA.com
    Getting Private key
    unable to write 'random state'
    Generating RSA private key, 1024 bit long modulus
    .........................++++++
    .................................................................++++++
    unable to write 'random state'
    e is 65537 (0x10001)
    Signature ok
    subject=/C=US/ST=WA/L=Provo/O=FakeClient/CN=FakeClient.com
    Getting CA Private Key
    unable to write 'random state'
    Generating RSA private key, 1024 bit long modulus
    ....++++++
    .........................++++++
    unable to write 'random state'
    e is 65537 (0x10001)
    Signature ok
    subject=/C=US/ST=WA/L=Provo/O=FakeServer/CN=FakeServer.com
    Getting CA Private Key
    unable to write 'random state'
```
    NOTE: there is a warning "unable to write 'random state'", but it won't cause any issue.

2. Server
```
    E:\pop\repo\OpenSSLTwowayauth>python server.py
    1
    X509 Cert Info
            commonName: FakeCA.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:17
            notAfter:  2021-07-12 19:31:17

    1
    X509 Cert Info
            commonName: FakeClient.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:18
            notAfter:  2021-07-12 19:31:18
```
3. Client
```
    E:\pop\repo\OpenSSLTwowayauth>python client.py
    in callback, cert result 1
    X509 Cert Info
            commonName: FakeCA.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:17
            notAfter:  2021-07-12 19:31:17

    in callback, cert result 1
    X509 Cert Info
            commonName: FakeServer.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:18
            notAfter:  2021-07-12 19:31:18

    ====SSL session certs[0]===
    X509 Cert Info
            commonName: FakeServer.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:18
            notAfter:  2021-07-12 19:31:18

    ====SSL session certs[1]===
    X509 Cert Info
            commonName: FakeCA.com
            SAN: None
            issuer: FakeCA.com
            notBefore: 2020-07-12 19:31:17
            notAfter:  2021-07-12 19:31:17
```
4. Get remote server SSL certificate
```
    E:\pop\repo\OpenSSLTwowayauth>python ssl-check.py --host www.google.com
    ====SSL session certs[0]===
    X509 Cert Info
            commonName: www.google.com
            SAN: ['www.google.com']
            issuer: GTS CA 1O1
            notBefore: 2020-06-17 14:31:22
            notAfter:  2020-09-09 14:31:22

    ====SSL session certs[1]===
    X509 Cert Info
            commonName: GTS CA 1O1
            SAN: None
            issuer: GlobalSign
            notBefore: 2017-06-15 00:00:42
            notAfter:  2021-12-15 00:00:42

    » www.google.com « … ('172.217.14.196', 443)
            commonName: www.google.com
            SAN: ['www.google.com']
            issuer: GTS CA 1O1
            notBefore: 2020-06-17 14:31:22
            notAfter:  2020-09-09 14:31:22
```