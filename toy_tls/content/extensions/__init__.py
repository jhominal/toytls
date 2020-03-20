from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from typing import ClassVar

from attr import attrs, attrib

from toy_tls._data_reader import DataReader
from toy_tls.validation import bounded_bytes


class ExtensionData(metaclass=ABCMeta):
    __slots__ = ()

    type: ClassVar[int]

    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'ExtensionData':
        raise NotImplementedError

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError


@attrs(auto_attribs=True, frozen=True, slots=True)
class UnknownExtension(ExtensionData):
    bytes: bytes = attrib(validator=bounded_bytes(max_length=0xffff))

    @classmethod
    def decode(cls, reader: DataReader) -> 'UnknownExtension':
        return UnknownExtension(bytes=reader.read_bytes_to_end())

    def encode(self) -> bytes:
        return self.bytes
