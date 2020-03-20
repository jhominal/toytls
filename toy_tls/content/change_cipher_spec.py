from __future__ import generator_stop

from typing import Optional, Sequence

from attr import attrs, attrib

from toy_tls._data_reader import DataReader
from toy_tls.content import ContentType, ContentMessage
from toy_tls.enum_with_data import EnumUInt8WithData


class ChangeCipherSpecMessageType(EnumUInt8WithData):
    change_cipher_spec = 1


@attrs(auto_attribs=True, slots=True)
class ChangeCipherSpecMessage(ContentMessage):
    type = ContentType.change_cipher_spec
    message_type: ChangeCipherSpecMessageType = attrib(default=ChangeCipherSpecMessageType.change_cipher_spec)

    @classmethod
    def next_message_size(cls, data: Sequence[int]) -> Optional[int]:
        return 1

    @classmethod
    def decode(cls, reader: DataReader) -> 'ChangeCipherSpecMessage':
        return ChangeCipherSpecMessage(
            message_type=ChangeCipherSpecMessageType.decode(reader),
        )

    def encode(self) -> bytes:
        return bytes([self.message_type.value])
