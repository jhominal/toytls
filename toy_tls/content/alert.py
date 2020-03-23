from __future__ import generator_stop

from typing import Optional, Sequence

from attr import attrs

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content import ContentType, ContentMessage
from toy_tls.enum_with_data import EnumUInt8WithData


class AlertLevel(EnumUInt8WithData):
    warning = 1
    fatal = 2


class AlertDescription(EnumUInt8WithData):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed_RESERVED = 21
    record_overflow = 22
    decompression_failure = 30
    handshake_failure = 40
    no_certificate_RESERVED = 41
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction_RESERVED = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    no_renegotiation = 100
    unsupported_extension = 110


@attrs(auto_attribs=True, slots=True)
class AlertMessage(ContentMessage):
    type = ContentType.alert
    level: AlertLevel
    description: AlertDescription

    @classmethod
    def next_message_size(cls, data: Sequence[int]) -> Optional[int]:
        return 2

    @classmethod
    def decode(cls, reader: DataReader) -> 'AlertMessage':
        return AlertMessage(
            level=AlertLevel.decode(reader),
            description=AlertDescription.decode(reader),
        )

    def encode(self, writer: DataWriter):
        writer.write(self.level)
        writer.write(self.description)
