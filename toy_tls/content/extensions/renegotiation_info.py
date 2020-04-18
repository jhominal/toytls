from __future__ import generator_stop

from attr import attrs

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content.extensions import ExtensionData


@attrs(auto_attribs=True, slots=True, frozen=True)
class RenegotiationInfo(ExtensionData):
    type = 0xff01

    data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'RenegotiationInfo':
        return RenegotiationInfo(data=reader.read_bytes(reader.read_byte()))

    def encode(self, writer: DataWriter):
        with writer.length_byte():
            writer.write_bytes(self.data)
