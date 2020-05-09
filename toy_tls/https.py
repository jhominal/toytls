from __future__ import generator_stop

import asyncio
import sys
import logging
from argparse import ArgumentParser, FileType
from typing import BinaryIO, Optional, Sequence
from urllib.parse import urlsplit, SplitResult, urlunsplit

from toy_tls.certificate import KeyPairValidationError
from toy_tls.connection import TLSConnection
from toy_tls.pem import load_cert_and_key, load_certs

logging.basicConfig(level='DEBUG')

logger = logging.getLogger(__name__)


async def run(
        url: str,
        cert_file: Optional[BinaryIO],
        key_file: Optional[BinaryIO],
        key_password: Optional[bytes],
        cert_chain_files: Optional[Sequence[BinaryIO]],
):
    if cert_file is not None:
        client_certificate = load_cert_and_key(cert_file=cert_file, key_file=key_file, key_password=key_password)
        try:
            client_certificate.check_key_pair()
        except KeyPairValidationError as e:
            logger.error(f'Configured key pair does not work: {e}')
            client_certificate = None
    else:
        client_certificate = None
    if client_certificate is not None and cert_chain_files is not None:
        cert_chain = load_certs(cert_files=cert_chain_files)
    else:
        cert_chain = []

    parsed_url: SplitResult = urlsplit(url)
    port = parsed_url.port
    hostname = parsed_url.hostname
    if port is None and parsed_url.scheme == 'https':
        port = 443
    reader, writer = await asyncio.open_connection(host=hostname, port=port, ssl=None)
    connection = TLSConnection(
        reader=reader,
        writer=writer,
        hostname=hostname,
        client_certificate=client_certificate,
        certificate_chain=cert_chain,
    )
    await connection.do_initial_handshake()
    relative_url = SplitResult(scheme='', netloc='', path=parsed_url.path, query=parsed_url.query, fragment='')
    http_data = (
        f'GET {urlunsplit(relative_url)} HTTP/1.1\r\n'
        f'Accept: */*\r\n'
        f'Host: {hostname}\r\n'
        f'User-Agent: curl\r\n'
        f'\r\n'
    ).encode('ascii')
    await connection.send_application_data(data=http_data)
    while not connection.closed():
        response_data = await connection.receive_application_data()
        print(response_data.decode('utf-8'), file=sys.stdout)


def main(
        url: str,
        cert_file: Optional[BinaryIO],
        key_file: Optional[BinaryIO],
        key_password: Optional[bytes],
        cert_chain_files: Optional[Sequence[BinaryIO]],
):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(
            url=url,
            cert_file=cert_file,
            key_file=key_file,
            key_password=key_password,
            cert_chain_files=cert_chain_files,
        )
    )
    loop.close()


parser = ArgumentParser("Open a TLS connection with target server and send a GET HTTPS request on the given URL.")
parser.add_argument('url')
parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')
parser.add_argument('--cert', type=FileType('rb'), help='A client certificate to use, in PEM format. May include the private key.')
parser.add_argument('--key', type=FileType('rb'), help='The private key of the client certificate, in PEM format.')
parser.add_argument('--key-password', help='The password to the private key, if it is encrypted.')
parser.add_argument('--prompt-key-password', action='store_true', help='Prompt for the password to the private key.')
parser.add_argument('--cert-chain', action='append', type=FileType('rb'), help='An element in the certificate chain, to send at the same time as the client certificate.')

if __name__ == '__main__':
    arguments = parser.parse_args()

    if arguments.prompt_key_password:
        key_pwd = input('Key password: ')
    else:
        key_pwd = arguments.key_password

    main(
        url=arguments.url,
        cert_file=arguments.cert,
        key_file=arguments.key,
        key_password=key_pwd,
        cert_chain_files=arguments.cert_chain,
    )
