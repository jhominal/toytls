from __future__ import generator_stop

from abc import abstractmethod, ABCMeta
from typing import ClassVar, Optional, Union, Sequence

from attr import attrs

from toy_tls._data_reader import DataReader
from toy_tls.enum_with_data import EnumUInt8WithData


class ContentType(EnumUInt8WithData):
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23


@attrs(auto_attribs=True, slots=True)
class ContentMessage(metaclass=ABCMeta):
    type: ClassVar[ContentType]

    @classmethod
    @abstractmethod
    def next_message_size(cls, data: Sequence[int]) -> Optional[int]:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'ContentMessage':
        raise NotImplementedError

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError


class ApplicationDataMessage(ContentMessage):
    type = ContentType.application_data

    def __init__(self, data: bytes):
        super().__init__()
        self.data = data

    @classmethod
    def next_message_size(cls, data: Sequence[int]) -> Optional[int]:
        return len(data)

    @classmethod
    def decode(cls, reader: DataReader) -> 'ApplicationDataMessage':
        return ApplicationDataMessage(reader.read_bytes_to_end())

    def encode(self):
        return self.data
