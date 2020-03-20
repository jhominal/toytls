from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from struct import Struct
from typing import Type, Sequence, TypeVar
from typing_extensions import Protocol

from attr import attrs, attrib


class InsufficientData(Exception):
    pass


T = TypeVar('T')


class SupportsDecode(Protocol):
    @classmethod
    def decode(cls: Type[T], reader: 'DataReader') -> T:
        raise NotImplementedError


_uint16_struct = Struct('>H')
_uint24_struct = Struct('>BH')


class DataReader(metaclass=ABCMeta):
    __slots__ = ()

    @property
    @abstractmethod
    def _limit(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def _data(self) -> bytes:
        raise NotImplementedError()

    @property
    @abstractmethod
    def _pos(self) -> int:
        raise NotImplementedError()

    @_pos.setter
    @abstractmethod
    def _pos(self, value):
        raise NotImplementedError()

    @abstractmethod
    def limited(self, size: int) -> 'DataReader':
        raise NotImplementedError()

    def read_byte(self) -> int:
        if self._pos + 1 > self._limit:
            raise InsufficientData
        v = self._data[self._pos]
        self._pos += 1
        return v

    def read_bytes(self, size: int) -> bytes:
        if size < 0:
            raise ValueError(f"size must be >= 0 but was {size}")
        if self._pos + size > self._limit:
            raise InsufficientData
        v = self._data[self._pos:self._pos + size]
        self._pos += size
        return v

    def read_uint16(self) -> int:
        if self._pos + _uint16_struct.size > self._limit:
            raise InsufficientData
        v, = _uint16_struct.unpack_from(self._data, offset=self._pos)
        self._pos += _uint16_struct.size
        return v

    def read_uint24(self) -> int:
        if self._pos + _uint24_struct.size > self._limit:
            raise InsufficientData
        msb, lsb = _uint24_struct.unpack_from(self._data, offset=self._pos)
        self._pos += _uint24_struct.size
        return msb << 16 | lsb

    def read_bytes_to_end(self) -> bytes:
        v = self._data[self._pos:self._limit]
        self._pos = self._limit
        return v

    def read_sequence(self, data_type: Type[T]) -> Sequence[T]:
        result = []
        while self._limit > self._pos:
            result.append(data_type.decode(self))
        if self._limit != self._pos:
            raise InsufficientData
        return result

    @property
    def remaining_data_length(self) -> int:
        return self._limit - self._pos

    @property
    def at_end_of_data(self) -> bool:
        return self._pos + 1 > self._limit


@attrs(auto_attribs=True, slots=True)
class FullDataReader(DataReader):
    _data: bytes
    _pos: int = attrib(default=0, init=False)

    @property
    def _limit(self):
        return len(self._data)

    def limited(self, size: int) -> 'DataReader':
        parent = self
        return LimitedDataReader(parent=parent, limit=min(self._pos + size, self._limit))


@attrs(auto_attribs=True, slots=True)
class LimitedDataReader(DataReader):
    _parent: FullDataReader
    _limit: int

    @property
    def _data(self):
        return self._parent._data

    @property
    def _pos(self):
        return self._parent._pos

    @_pos.setter
    def _pos(self, value):
        self._parent._pos = value

    def limited(self, size: int) -> 'DataReader':
        parent = self._parent
        return LimitedDataReader(parent=parent, limit=min(self._pos + size, self._limit))
