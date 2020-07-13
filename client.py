from OpenSSL import SSL
from socket import socket
import os
import Utils


CERT_PATH = "certs/client.cer"
CERT_CHAIN_PATH = "certs/chain.cer"
CERT_PRIVATE_KEY_PATH = "certs/client.key"

def verify_callback(connection, x509, errnum, errdepth, ok):
    print("in callback, cert result %d" % (ok))
    Utils.print_cert_info(x509.to_cryptography())
    return True

def get_certificate(hostname, port):
    sock = socket()

    sock.connect((hostname, port))
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    ctx.use_certificate_file(CERT_PATH)
    ctx.load_verify_locations(CERT_CHAIN_PATH)
    ctx.use_privatekey_file(CERT_PRIVATE_KEY_PATH)
    ctx.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_callback
        )
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.do_handshake()
   
    certs = sock_ssl.get_peer_cert_chain()
    for pos, cert in enumerate(certs):
        print("====SSL session certs[" + str(pos) + "]===")
        Utils.print_cert_info(cert.to_cryptography())

    sock_ssl.close()
    sock.close()

if __name__ == '__main__':    
    get_certificate("127.0.0.1", 8070)
