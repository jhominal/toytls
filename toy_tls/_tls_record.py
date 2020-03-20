from __future__ import generator_stop

import struct
from abc import ABCMeta, abstractmethod

from attr import attrs, attrib

from toy_tls._common import ProtocolVersion
from toy_tls._data_reader import DataReader
from toy_tls.content import ContentType
from toy_tls.validation import bounded_bytes


@attrs(auto_attribs=True, frozen=True, slots=True)
class TLSRecordHeader:
    content_type: ContentType
    protocol_version: ProtocolVersion
    data_length: int

    @classmethod
    def decode(cls, data_reader: DataReader) -> 'TLSRecordHeader':
        content_type = ContentType.decode(data_reader)
        protocol_version = ProtocolVersion.decode(data_reader)
        data_length = data_reader.read_uint16()
        return TLSRecordHeader(
            content_type=content_type,
            protocol_version=protocol_version,
            data_length=data_length,
        )


@attrs(auto_attribs=True, frozen=True, slots=True)
class TLSPlaintextRecord:
    content_type: ContentType
    protocol_version: ProtocolVersion
    data: bytes = attrib(validator=bounded_bytes(max_length=1 << 14))


class TLSRecordEncoder(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def encode(self, sequence_number: int, record: TLSPlaintextRecord) -> bytes:
        raise NotImplementedError


class TLSRecordDecoder(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def decode(self, expected_sequence_number: int, header: TLSRecordHeader, data_reader: DataReader) -> TLSPlaintextRecord:
        raise NotImplementedError


class InitialTLSRecordEncoder(TLSRecordEncoder):
    def encode(self, sequence_number, record: TLSPlaintextRecord) -> bytes:
        buf = bytearray()
        buf.extend(record.content_type.encode())
        buf.extend(record.protocol_version.encode())
        buf.extend(struct.pack('>H', len(record.data)))
        buf.extend(record.data)
        return bytes(buf)


class InitialTLSRecordDecoder(TLSRecordDecoder):
    def decode(self, expected_sequence_number: int, header: TLSRecordHeader, data_reader: DataReader) -> TLSPlaintextRecord:
        return TLSPlaintextRecord(
            content_type=header.content_type,
            protocol_version=header.protocol_version,
            data=data_reader.read_bytes(header.data_length),
        )
