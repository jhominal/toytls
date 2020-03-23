from __future__ import generator_stop

from abc import ABCMeta
from struct import pack, pack_into

from attr import attrs, attrib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from toy_tls._common import ProtocolVersion
from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls._tls_record import TLSRecordEncoder, TLSRecordDecoder, TLSRecordHeader, TLSPlaintextRecord
from toy_tls.content import ContentType
from toy_tls.encryption import EncryptionEngine


def additional_data(sequence_number: int, content_type: ContentType, protocol_version: ProtocolVersion, length: int) -> bytes:
    return pack('>QBHH', sequence_number, content_type.value, protocol_version.value, length)


class AEADEngine(EncryptionEngine, metaclass=ABCMeta):
    __slots__ = ()

    @property
    def mac_key_length(self) -> int:
        return 0


class AESGCMTLSRecordDecoder(TLSRecordDecoder):
    def __init__(self, key: bytes, salt: bytes):
        self.cipher = AESGCM(key)
        self.salt = salt

    def decode(self, expected_sequence_number: int, header: TLSRecordHeader,
               data_reader: DataReader) -> TLSPlaintextRecord:
        nonce_explicit = data_reader.read_bytes(8)
        encrypted_data = data_reader.read_bytes_to_end()
        plaintext_data = self.cipher.decrypt(
            nonce=self.salt + nonce_explicit,
            data=encrypted_data,
            associated_data=additional_data(
                sequence_number=expected_sequence_number,
                content_type=header.content_type,
                protocol_version=header.protocol_version,
                length=header.data_length - 8 - 16,
            ),
        )
        return TLSPlaintextRecord(
            content_type=header.content_type,
            protocol_version=header.protocol_version,
            data=plaintext_data,
        )


class AESGCMTLSRecordEncoder(TLSRecordEncoder):
    def __init__(self, key: bytes, salt: bytes):
        self.cipher = AESGCM(key)
        self.salt = salt

    def encode(self, sequence_number: int, record: TLSPlaintextRecord) -> bytes:
        nonce_explicit = pack('>Q', sequence_number)
        encrypted_data = self.cipher.encrypt(
            nonce=self.salt + nonce_explicit,
            data=record.data,
            associated_data=additional_data(
                sequence_number=sequence_number,
                content_type=record.content_type,
                protocol_version=record.protocol_version,
                length=len(record.data),
            ),
        )

        writer = DataWriter()
        writer.write(record.content_type)
        writer.write(record.protocol_version)
        with writer.length_uint16():
            writer.write_bytes(nonce_explicit)
            writer.write_bytes(encrypted_data)

        return writer.to_bytes()


@attrs(auto_attribs=True, slots=True, frozen=True)
class AESGCMEngine(AEADEngine):
    enc_key_length: int = attrib()

    @enc_key_length.validator
    def validate_enc_key_length(self, attribute, value):
        if value not in (16, 32):
            raise ValueError('Encryption key length must be either 16 for AES_128 or 32 for AES_256.')

    @property
    def fixed_iv_length(self) -> int:
        return 4

    def decoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordDecoder:
        self._validate(mac_key=mac_key, enc_key=enc_key, fixed_iv=fixed_iv)
        return AESGCMTLSRecordDecoder(key=enc_key, salt=fixed_iv)

    def encoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordEncoder:
        self._validate(mac_key=mac_key, enc_key=enc_key, fixed_iv=fixed_iv)
        return AESGCMTLSRecordEncoder(key=enc_key, salt=fixed_iv)


def _chacha20_poly1305_nonce(sequence_number: int, iv: bytes) -> bytes:
    if len(iv) != 12:
        raise ValueError('iv must have 12 bytes.')
    buf = bytearray(12)
    pack_into('>Q', buf, 4, sequence_number)

    for i in range(12):
        buf[i] ^= iv[i]

    return bytes(buf)


class ChaCha20Poly1305TLSRecordDecoder(TLSRecordDecoder):
    def __init__(self, key: bytes, iv: bytes):
        self.cipher = ChaCha20Poly1305(key)
        self.iv = iv

    def decode(self, expected_sequence_number: int, header: TLSRecordHeader,
               data_reader: DataReader) -> TLSPlaintextRecord:
        encrypted_data = data_reader.read_bytes_to_end()
        plaintext_data = self.cipher.decrypt(
            nonce=_chacha20_poly1305_nonce(sequence_number=expected_sequence_number, iv=self.iv),
            data=encrypted_data,
            associated_data=additional_data(
                sequence_number=expected_sequence_number,
                content_type=header.content_type,
                protocol_version=header.protocol_version,
                length=header.data_length - 16,
            ),
        )
        return TLSPlaintextRecord(
            content_type=header.content_type,
            protocol_version=header.protocol_version,
            data=plaintext_data,
        )


class ChaCha20Poly1305TLSRecordEncoder(TLSRecordEncoder):
    def __init__(self, key: bytes, iv: bytes):
        self.cipher = ChaCha20Poly1305(key)
        self.iv = iv

    def encode(self, sequence_number: int, record: TLSPlaintextRecord) -> bytes:
        encrypted_data = self.cipher.encrypt(
            nonce=_chacha20_poly1305_nonce(sequence_number=sequence_number, iv=self.iv),
            data=record.data,
            associated_data=additional_data(
                sequence_number=sequence_number,
                content_type=record.content_type,
                protocol_version=record.protocol_version,
                length=len(record.data),
            ),
        )

        writer = DataWriter()
        writer.write(record.content_type)
        writer.write(record.protocol_version)
        with writer.length_uint16():
            writer.write_bytes(encrypted_data)

        return writer.to_bytes()


class ChaCha20Poly1305Engine(AEADEngine):
    @property
    def enc_key_length(self) -> int:
        return 32

    @property
    def fixed_iv_length(self) -> int:
        return 12

    def decoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordDecoder:
        self._validate(mac_key=mac_key, enc_key=enc_key, fixed_iv=fixed_iv)
        return ChaCha20Poly1305TLSRecordDecoder(key=enc_key, iv=fixed_iv)

    def encoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordEncoder:
        self._validate(mac_key=mac_key, enc_key=enc_key, fixed_iv=fixed_iv)
        return ChaCha20Poly1305TLSRecordEncoder(key=enc_key, iv=fixed_iv)
