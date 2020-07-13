# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from socket import socket
from collections import namedtuple
import idna
import os

def verify_certificate(leaf_cert_path, trusted_root_cert_path):
    leaf_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(leaf_cert_path).read())
    print_cert_info(leaf_cert)
    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(trusted_root_cert_path).read())
    print_cert_info(root_cert)
    if verify_certificate_chain(leaf_cert, root_cert):
        print("Successfully verified leaf cert:"+leaf_cert_path)

def verify_certificate_chain(leaf_cert, trusted_root_cert):
    #Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()
        caPem = get_ca_ext(leaf_cert)
        caCert = crypto.load_certificate(crypto.FILETYPE_PEM, caPem)
        print_cert_info(caCert)

        store.add_cert(caCert)
        store.add_cert(trusted_root_cert)
        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, leaf_cert)
        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print(e)
        return False



def get_ca_ext(cert):
    crypto_cert = cert.to_cryptography()
    caExtOid = "1.2.840.113556.1.8000.2554.197254.100"
    caPemStr = ''
    for ext in crypto_cert.extensions:
        if caExtOid in str(ext.oid):
            caPemStr = ext.value.value
    return caPemStr

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()

    certs = sock_ssl.get_peer_cert_chain()
    for pos, cert in enumerate(certs):
        print("====SSL session certs[" + str(pos) + "]===")
        fd = os.open("cert"+str(pos)+".pem", os.O_RDWR|os.O_CREAT)
        os.write(fd, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        os.close(fd)
        print_cert_info(cert.to_cryptography())
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None
    except ValueError as ve:
        print(ve)
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def print_cert_info(cert):
    s = '''X509 Cert Info
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            commonname=get_common_name(cert),
            SAN=get_alt_names(cert),
            issuer=get_issuer(cert),
            notbefore=cert.not_valid_before,
            notafter=cert.not_valid_after
    )
    print(s)

def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)

if __name__ == '__main__':
    verify_certificate("CY2TAP3BC29843C.MFC.cer","ApPrssRoot.cer")