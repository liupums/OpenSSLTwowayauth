from OpenSSL import SSL
from socket import socket
import os
import Utils
import base64

CERT_PATH = "certs/client.cer"
CERT_CHAIN_PATH = "certs/chain.cer"
CERT_PRIVATE_KEY_PATH = "certs/client.key"

def verify_callback(connection, x509, errnum, errdepth, ok):
    print("in callback, cert result %d" % (ok))
    Utils.print_cert_info(x509.to_cryptography())
    return True

def sendReq(socket_ssl, host, path, user, passwd):
    token= ('%s:%s' % (user, passwd)).strip()
    token_bytes = token.encode('ascii')
    base64_token_bytes = base64.b64encode(token_bytes)
    base64_token = base64_token_bytes.decode('ascii')
    lines= [
        'GET %s HTTP/1.1' % path,
        'Host: %s' % host,
        'Authorization: Basic %s' % (base64_token)
    ]
    request = '\r\n'.join(lines)+'\r\n\r\n'
    socket_ssl.send(request.encode())
    from_server = bytearray()
    while True:
        try:
            data = socket_ssl.recv(4096)
            if not data: 
                from_server.decode()
            from_server.extend(data)
        except: 
            break
    return from_server.decode()

def restApi(hostname, port, api, user, passwd):
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
 
    # send some data 
    response = sendReq(sock_ssl, hostname, api, user, passwd)
    print("====reponse[\r\n" + response + "\r\n]===")
    
    sock_ssl.close()
    sock.close()

if __name__ == '__main__':    
    import argparse
    import Utils
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', action='store', dest='host',
                        help='remote server hostname or Ip Address')

    parser.add_argument('--port', action='store', dest='port', type=int, default=443,
                        help='remote port number, default 443')

    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    parser.add_argument('--api', action='store', dest='api',
                        help='rest API path')

    parser.add_argument('--user', action='store', dest='user',
                        help='basic auth user name')

    parser.add_argument('--passwd', action='store', dest='passwd',
                        help='basic auth user password')

    results = parser.parse_args()
    restApi(results.host, results.port, results.api, results.user, results.passwd)
