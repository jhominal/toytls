from __future__ import generator_stop

import asyncio
import sys
import logging
from argparse import ArgumentParser
from urllib.parse import urlsplit, SplitResult, urlunsplit

from toy_tls.connection import TLSConnection


logging.basicConfig(level='DEBUG')


async def run(url: str):
    parsed_url: SplitResult = urlsplit(url)
    port = parsed_url.port
    hostname = parsed_url.hostname
    if port is None and parsed_url.scheme == 'https':
        port = 443
    reader, writer = await asyncio.open_connection(host=hostname, port=port, ssl=None)
    connection = TLSConnection(reader=reader, writer=writer)
    await connection.do_initial_handshake(hostname=hostname)
    relative_url = SplitResult(scheme='', netloc='', path=parsed_url.path, query=parsed_url.query, fragment='')
    http_data = f'GET {urlunsplit(relative_url)} HTTP/1.1\r\nAccept: */*\r\nHost: {hostname}\r\n\r\n'.encode('ascii')
    await connection.send_application_data(data=http_data)
    response_data = await connection.receive_application_data()
    print(response_data.decode('utf-8'), file=sys.stdout)


def main(url: str):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(url=url))
    loop.close()


parser = ArgumentParser("Open a TLS connection with target server and send a GET HTTPS request on the given URL.")
parser.add_argument('url')
parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')

if __name__ == '__main__':
    arguments = parser.parse_args()
    main(url=arguments.url)
