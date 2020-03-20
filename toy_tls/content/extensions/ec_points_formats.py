from __future__ import generator_stop

from typing import Sequence

from attr import attrs, attrib

from toy_tls._data_reader import DataReader
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt8WithData


class EllipticCurvePointFormat(EnumUInt8WithData):
    uncompressed = 0


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
        byte_length = len(self.supported_formats)
        buf = bytearray()
        buf.append(byte_length)
        for f in self.supported_formats:
            buf.extend(f.encode())
        return bytes(buf)
