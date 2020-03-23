from __future__ import generator_stop

from abc import ABCMeta, abstractmethod

from attr import attrs, attrib

from toy_tls._common import ProtocolVersion
from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
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
    def encode(self, sequence_number: int, record: TLSPlaintextRecord, writer: DataWriter):
        raise NotImplementedError


class TLSRecordDecoder(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def decode(self, expected_sequence_number: int, header: TLSRecordHeader, data_reader: DataReader) -> TLSPlaintextRecord:
        raise NotImplementedError


class InitialTLSRecordEncoder(TLSRecordEncoder):
    def encode(self, sequence_number, record: TLSPlaintextRecord, writer: DataWriter):
        writer.write(record.content_type)
        writer.write(record.protocol_version)
        with writer.length_uint16():
            writer.write_bytes(record.data)


class InitialTLSRecordDecoder(TLSRecordDecoder):
    def decode(self, expected_sequence_number: int, header: TLSRecordHeader, data_reader: DataReader) -> TLSPlaintextRecord:
        return TLSPlaintextRecord(
            content_type=header.content_type,
            protocol_version=header.protocol_version,
            data=data_reader.read_bytes(header.data_length),
        )
