# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

if __name__ == '__main__':
    import argparse
    import Utils
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', action='store', dest='host',
                        help='remote server hostname or Ip Address')

    parser.add_argument('--port', action='store', dest='port', type=int, default=443,
                        help='remote port number, default 443')

    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    results = parser.parse_args()
    hostinfo = Utils.get_certificate(results.host, results.port)
    Utils.print_basic_info(hostinfo)