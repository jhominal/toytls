from __future__ import generator_stop

from enum import Enum

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter


class EnumWithData(Enum):
    def __new__(cls, value, *args):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.__init__(value, *args)
        return obj

    def __init__(self, value, *args):
        pass

    @classmethod
    def from_value(cls, value):
        return cls(value)


class EnumUInt8WithData(EnumWithData):
    def __init__(self, value: int, *args):
        if not isinstance(value, int) or value < 0 or value > 0xff:
            raise ValueError('value must be an integer between 0 and 255.')
        super().__init__(value, *args)

    @classmethod
    def decode(cls, reader: DataReader):
        return cls(reader.read_byte())

    def encode(self, writer: DataWriter):
        writer.write_byte(self.value)


class EnumUInt16WithData(EnumWithData):
    def __init__(self, value: int, *args):
        if not isinstance(value, int) or value < 0 or value > 0xffff:
            raise ValueError('value must be an integer between 0 and 65535.')
        super().__init__(value, *args)

    @classmethod
    def decode(cls, reader: DataReader):
        return cls(reader.read_uint16())

    def encode(self, writer: DataWriter):
        writer.write_uint16(self.value)
