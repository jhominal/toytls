from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from typing import Type, ClassVar, Sequence, Optional

from attr import attrs

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
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
    def encode(self, writer: DataWriter):
        raise NotImplementedError()


@attrs(auto_attribs=True, slots=True, frozen=True)
class HostName(ServerNameData):
    type = 0
    data: bytes

    @classmethod
    def decode(cls, data_reader: DataReader) -> 'HostName':
        data_length = data_reader.read_uint16()
        return HostName(data=data_reader.read_bytes(data_length))

    def encode(self, writer: DataWriter):
        with writer.length_uint16():
            writer.write_bytes(self.data)


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

    def encode(self, writer: DataWriter):
        writer.write(self.type)
        writer.write(self.data)


@attrs(auto_attribs=True, slots=True, frozen=True)
class ServerNameList(ExtensionData):
    @staticmethod
    def create(hostname: bytes):
        return ServerNameList(
            names=[ServerName(type=NameType.host_name, data=HostName(hostname))]
        )

    type = 0
    names: Optional[Sequence[ServerName]]

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerNameList':
        # When this extension is in ServerHello, it may have no data at all.
        if reader.at_end_of_data:
            return ServerNameList(names=None)

        names_length = reader.read_uint16()
        names = reader.limited(names_length).read_sequence(ServerName)
        return ServerNameList(names=names)

    def encode(self, writer: DataWriter):
        # When this extension is in ServerHello, it may have no data at all.
        if self.names is None:
            return

        with writer.length_uint16():
            for name in self.names:
                writer.write(name)
