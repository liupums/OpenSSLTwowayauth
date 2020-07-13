
'''
1. test two-way auth with openssl
   $> openssl s_client -showcerts -connect 127.0.0.1:8070 -cert certs\client.cer -key certs\client.key
    GET / HTTP/1.1                    <===type this, then press "enter"

        HTTP/1.1 200 OK
        Content-type: text/plain
        Transfer-Encoding: chunked
        Date: Sun, 12 Jul 2020 18:48:30 GMT
        Server: www.cherrypy.example

        c
        Hello world!
        0

    QUIT                             <===type this, then press "enter"
        DONE

2. test with curl (sschannel will automatically pick up the client cert)
   curl -vv https://FakeServer.com:8070 --ssl-no-revoke  --resolve FakeServer.com:8070:127.0.0.1
'''

import cherrypy
from cheroot.wsgi import Server as CherryPyWSGIServer
from cheroot.ssl.pyopenssl import pyOpenSSLAdapter
from OpenSSL import crypto,SSL
import Utils

CERT_PATH = "certs/server.cer"
CERT_CHAIN_PATH = "certs/chain.cer"
CERT_PRIVATE_KEY_PATH = "certs/server.key"

def my_crazy_app(environ, start_response):
    status = '200 OK'
    response_headers = [('Content-type','text/plain')]
    start_response(status, response_headers)
    return [b'Hello world!']

def verify_callback(connection, x509, errnum, errdepth, ok):
    print("in callback, cert result %d" % (ok))
    Utils.print_cert_info(x509.to_cryptography())
    return True

if __name__ == '__main__':    
    server = CherryPyWSGIServer(
        ('0.0.0.0', 8070), my_crazy_app,
        server_name='www.cherrypy.example')
    server.ssl_adapter = pyOpenSSLAdapter (certificate=CERT_PATH,
    	certificate_chain=CERT_CHAIN_PATH,
        private_key=CERT_PRIVATE_KEY_PATH)
    server.ssl_adapter.context = SSL.Context(SSL.SSLv23_METHOD)
    server.ssl_adapter.context.use_certificate_file(CERT_PATH)
    server.ssl_adapter.context.load_verify_locations(CERT_CHAIN_PATH)
    server.ssl_adapter.context.use_privatekey_file(CERT_PRIVATE_KEY_PATH)
    server.ssl_adapter.context.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_callback
        )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
 