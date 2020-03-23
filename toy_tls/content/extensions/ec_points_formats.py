from __future__ import generator_stop

from typing import Sequence

from attr import attrs, attrib

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt8WithData


class EllipticCurvePointFormat(EnumUInt8WithData):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2


@attrs(auto_attribs=True, slots=True, frozen=True)
class EllipticCurvePointFormatList(ExtensionData):
    type = 11

    supported_formats: Sequence[EllipticCurvePointFormat] = attrib(default=(EllipticCurvePointFormat.uncompressed,))

    @classmethod
    def decode(cls, reader: DataReader) -> 'EllipticCurvePointFormatList':
        length = reader.read_byte()
        return EllipticCurvePointFormatList(
            supported_formats=reader.limited(length).read_sequence(EllipticCurvePointFormat),
        )

    def encode(self) -> bytes:
        writer = DataWriter()
        with writer.length_byte():
            for f in self.supported_formats:
                writer.write(f)
        return writer.to_bytes()
