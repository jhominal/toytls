from __future__ import generator_stop

from toy_tls._data_reader import DataReader
from toy_tls.content.extensions import ExtensionData


class EncryptThenMac(ExtensionData):
    type = 22

    @classmethod
    def decode(cls, reader: DataReader) -> 'EncryptThenMac':
        return EncryptThenMac()

    def encode(self) -> bytes:
        return b''
