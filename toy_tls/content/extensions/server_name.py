from __future__ import generator_stop

import struct
from abc import ABCMeta, abstractmethod
from typing import Type, ClassVar, Sequence

from attr import attrs

from toy_tls._data_reader import DataReader
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt8WithData


class ServerNameData(metaclass=ABCMeta):
    type: ClassVar[int]
    __slots__ = ()

    @classmethod
    @abstractmethod
    def decode(cls, data_reader: DataReader) -> 'ServerNameData':
        raise NotImplementedError()

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError()


@attrs(auto_attribs=True, slots=True, frozen=True)
class HostName(ServerNameData):
    type = 0
    data: bytes

    @classmethod
    def decode(cls, data_reader: DataReader) -> 'HostName':
        data_length = data_reader.read_uint16()
        return HostName(data=data_reader.read_bytes(data_length))

    def encode(self) -> bytes:
        return struct.pack('>H', len(self.data)) + self.data


class NameType(EnumUInt8WithData):
    host_name = (HostName.type, HostName)

    def __init__(self, value: int, codec_class: Type[ServerNameData]):
        super().__init__(value, codec_class)
        self.codec_class = codec_class


@attrs(auto_attribs=True, slots=True, frozen=True)
class ServerName:
    type: NameType
    data: ServerNameData

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerName':
        name_type = NameType.decode(reader)
        name_data = name_type.codec_class.decode(reader)
        return ServerName(
            type=name_type,
            data=name_data,
        )

    def encode(self) -> bytes:
        return self.type.encode() + self.data.encode()


@attrs(auto_attribs=True, slots=True, frozen=True)
class ServerNameList(ExtensionData):
    @staticmethod
    def create(hostname: bytes):
        return ServerNameList(
            names=[ServerName(type=NameType.host_name, data=HostName(hostname))]
        )

    type = 0
    names: Sequence[ServerName]

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerNameList':
        names_length = reader.read_uint16()
        names = reader.limited(names_length).read_sequence(ServerName)
        return ServerNameList(names=names)

    def encode(self) -> bytes:
        buffer = bytearray()
        for name in self.names:
            buffer.extend(name.encode())
        return struct.pack('>H', len(buffer)) + bytes(buffer)

