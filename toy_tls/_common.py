from __future__ import generator_stop

from toy_tls.enum_with_data import EnumUInt8WithData, EnumUInt16WithData


class ProtocolVersion(EnumUInt16WithData):
    SSL_2 = 0x0200
    SSL_3 = 0x0300
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303

    def __lt__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value >= other.value


class CompressionMethod(EnumUInt8WithData):
    null = 0
