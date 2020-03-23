from __future__ import generator_stop

from contextlib import contextmanager
from struct import Struct

from attr import attrs, attrib
from typing_extensions import Protocol


class IntFieldOverflow(Exception):
    pass


class SupportsEncode(Protocol):
    def encode(self) -> bytes:
        raise NotImplementedError


_uint16_struct = Struct('>H')
_uint24_struct = Struct('>BH')


@attrs(auto_attribs=True, slots=True)
class DataWriter:
    _buffer: bytearray = attrib(init=False, factory=bytearray)

    def write(self, v: SupportsEncode):
        self._buffer.extend(v.encode())

    def write_byte(self, v: int):
        if v > 0xFF:
            raise IntFieldOverflow
        self._buffer.append(v)

    def write_bytes(self, data: bytes):
        self._buffer.extend(data)

    def write_uint16(self, v: int):
        if v > 0xFFFF:
            raise IntFieldOverflow
        self._buffer.extend(_uint16_struct.pack(v))

    @contextmanager
    def length_byte(self):
        offset = len(self._buffer)
        self._buffer.append(0)
        yield
        data_length = len(self._buffer) - offset - 1
        if data_length > 0xFF:
            raise IntFieldOverflow
        self._buffer[offset] = data_length

    @contextmanager
    def length_uint16(self):
        offset = len(self._buffer)
        self._buffer.extend((0, 0))
        yield
        data_length = len(self._buffer) - offset - 2
        if data_length > 0xFFFF:
            raise IntFieldOverflow
        _uint16_struct.pack_into(self._buffer, offset, data_length)

    @contextmanager
    def length_uint24(self):
        offset = len(self._buffer)
        self._buffer.extend((0, 0, 0))
        yield
        data_length = len(self._buffer) - offset - 3
        if data_length > 0xFFFFFF:
            raise IntFieldOverflow
        msb, lsb = (data_length & 0xFF0000) >> 16, data_length & 0xFFFF
        _uint24_struct.pack_into(self._buffer, offset, msb, lsb)

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)
