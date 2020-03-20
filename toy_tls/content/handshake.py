from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from struct import pack, unpack_from
from typing import ClassVar, Sequence, Type, Optional, List

from attr import attrs, attrib
from attr.validators import instance_of, deep_iterable
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_der_x509_certificate

from toy_tls._cipher_suites import CipherSuite
from toy_tls._common import ProtocolVersion, CompressionMethod
from toy_tls._data_reader import DataReader
from toy_tls.content import ContentType, ContentMessage
from toy_tls.content.extensions import ExtensionData, UnknownExtension
from toy_tls.content.extensions.ec_points_formats import EllipticCurvePointFormatList
from toy_tls.content.extensions.elliptic_curves import NamedCurveList
from toy_tls.content.extensions.encrypt_then_mac import EncryptThenMac
from toy_tls.content.extensions.server_name import ServerNameList
from toy_tls.content.extensions.signature_algorithms import SupportedSignatureAlgorithms
from toy_tls.enum_with_data import EnumUInt8WithData, EnumUInt16WithData
from toy_tls.validation import fixed_bytes, bounded_bytes


class HandshakeMessageData(metaclass=ABCMeta):
    __slots__ = ()
    message_type: ClassVar[int]

    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'HandshakeMessageData':
        raise NotImplementedError

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError


# Sent by the server to initiate a renegotiation
@attrs(auto_attribs=True, slots=True)
class HelloRequest(HandshakeMessageData):
    message_type = 0

    @classmethod
    def decode(cls, reader: DataReader) -> 'HelloRequest':
        return HelloRequest()

    def encode(self) -> bytes:
        return b''


class ExtensionType(EnumUInt16WithData):
    server_name = (ServerNameList.type, ServerNameList)
    elliptic_curves = (NamedCurveList.type, NamedCurveList)
    ec_points_formats = (EllipticCurvePointFormatList.type, EllipticCurvePointFormatList)
    signature_algorithms = (SupportedSignatureAlgorithms.type, SupportedSignatureAlgorithms)
    encrypt_then_mac = (EncryptThenMac.type, EncryptThenMac)

    def __init__(self, value, data_type: Type[ExtensionData]):
        super().__init__(value, data_type)
        self.data_type = data_type

    @classmethod
    def _missing_(cls, value):
        # HACK: Create new member of Enum so that ExtensionType(<value>) returns the equivalent of
        #   unknown = (<value>, UnknownExtension)

        # noinspection PyArgumentList
        v = cls.__new_member__(cls, value, UnknownExtension)

        # _name_ attribute is necessary if we want the value to work right (e.g. with repr)
        v._name_ = 'unknown'
        return v


@attrs(auto_attribs=True, slots=True)
class Extension:
    @classmethod
    def from_data(cls, extension_data: ExtensionData) -> 'Extension':
        return Extension(
            type=ExtensionType.from_value(extension_data.type),
            data=extension_data,
        )

    type: ExtensionType = attrib(validator=instance_of(ExtensionType))
    data: ExtensionData = attrib(validator=instance_of(ExtensionData))

    @classmethod
    def decode(cls, reader: DataReader) -> 'Extension':
        extension_type = ExtensionType.decode(reader)
        extension_data_length = reader.read_uint16()

        return Extension(
            type=extension_type,
            data=extension_type.data_type.decode(reader.limited(extension_data_length)),
        )

    def encode(self) -> bytes:
        buf = bytearray()

        buf.extend(self.type.encode())

        data_bytes = self.data.encode()
        buf.extend(pack('>H', len(data_bytes)))
        buf.extend(data_bytes)

        return bytes(buf)


# Sent by the client at start or to initiate/reply to renegotiation
@attrs(auto_attribs=True, slots=True)
class ClientHello(HandshakeMessageData):
    message_type = 1
    client_version: ProtocolVersion = attrib(kw_only=True)
    random: bytes = attrib(validator=fixed_bytes(32), kw_only=True)
    session_id: bytes = attrib(default=b'', validator=bounded_bytes(max_length=32), kw_only=True)
    cipher_suites: Sequence[CipherSuite] = attrib(default=(), kw_only=True)
    compression_methods: Sequence[CompressionMethod] = attrib(default=(CompressionMethod.null,), kw_only=True)
    extensions: Sequence[Extension] = attrib(default=(), kw_only=True)

    @classmethod
    def decode(cls, reader: DataReader) -> 'ClientHello':
        client_version = ProtocolVersion.decode(reader)
        random = reader.read_bytes(32)

        session_id_len = reader.read_byte()
        session_id = reader.read_bytes(session_id_len)

        cipher_suites_byte_len = reader.read_uint16()
        cipher_suites = reader.limited(cipher_suites_byte_len).read_sequence(CipherSuite)

        compression_methods_byte_len = reader.read_byte()
        compression_methods = reader.limited(compression_methods_byte_len).read_sequence(CompressionMethod)

        if not reader.at_end_of_data:
            extensions_byte_len = reader.read_uint16()
            extensions = reader.limited(extensions_byte_len).read_sequence(Extension)
        else:
            extensions = ()

        return ClientHello(
            client_version=client_version,
            random=random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=extensions,
        )

    def encode(self) -> bytes:
        buf = bytearray()

        buf.extend(self.client_version.encode())
        buf.extend(self.random)

        buf.extend(pack('B', len(self.session_id)))
        buf.extend(self.session_id)

        buf.extend(pack('>H', 2 * len(self.cipher_suites)))
        for cs in self.cipher_suites:
            buf.extend(cs.encode())

        buf.extend(pack('B', len(self.compression_methods)))
        for cm in self.compression_methods:
            buf.extend(cm.encode())

        if len(self.extensions) > 0:
            extensions_byte_length = 0
            encoded_extensions = []
            for extension in self.extensions:
                encoded_extension = extension.encode()
                encoded_extensions.append(encoded_extension)
                extensions_byte_length += len(encoded_extension)
            buf.extend(pack('>H', extensions_byte_length))
            for encoded_extension in encoded_extensions:
                buf.extend(encoded_extension)

        return bytes(buf)


# Sent by the server after server has chosen cipher suite, compression method, extensions
@attrs(auto_attribs=True, slots=True)
class ServerHello(HandshakeMessageData):
    message_type = 2
    server_version: ProtocolVersion
    random: bytes = attrib(validator=fixed_bytes(32))
    session_id: bytes = attrib(validator=bounded_bytes(max_length=32))
    cipher_suite: CipherSuite
    compression_method: CompressionMethod
    extensions: Sequence[Extension]

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerHello':
        server_version = ProtocolVersion.decode(reader)
        random = reader.read_bytes(32)

        session_id_len = reader.read_byte()
        session_id = reader.read_bytes(session_id_len)

        cipher_suite = CipherSuite.decode(reader)
        compression_method = CompressionMethod.decode(reader)

        if not reader.at_end_of_data:
            extensions_byte_len = reader.read_uint16()
            extensions = reader.limited(extensions_byte_len).read_sequence(Extension)
        else:
            extensions = ()

        return ServerHello(
            server_version=server_version,
            random=random,
            session_id=session_id,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            extensions=extensions,
        )

    def encode(self) -> bytes:
        buf = bytearray()

        buf.extend(self.server_version.encode())
        buf.extend(self.random)

        buf.extend(pack('B', len(self.session_id)))
        buf.extend(self.session_id)

        buf.extend(self.cipher_suite.encode())
        buf.extend(self.compression_method.encode())

        if len(self.extensions) > 0:
            extensions_byte_length = 0
            encoded_extensions = []
            for extension in self.extensions:
                encoded_extension = extension.encode()
                encoded_extensions.append(encoded_extension)
                extensions_byte_length += len(encoded_extension)
            buf.extend(pack('>H', extensions_byte_length))
            for encoded_extension in encoded_extensions:
                buf.extend(encoded_extension)

        return bytes(buf)


@attrs(auto_attribs=True, slots=True)
class PeerCertificate(HandshakeMessageData):
    message_type = 11

    certificate_list: Sequence[Certificate] = attrib(validator=deep_iterable(instance_of(Certificate)))

    @classmethod
    def decode(cls, reader: DataReader) -> 'PeerCertificate':
        data_length = reader.read_uint24()
        reader = reader.limited(data_length)
        certs: List[Certificate] = []
        while not reader.at_end_of_data:
            cert_length = reader.read_uint24()
            cert_data = reader.read_bytes(cert_length)
            cert = load_der_x509_certificate(data=cert_data, backend=default_backend())
            certs.append(cert)
        return PeerCertificate(certificate_list=tuple(certs))

    def encode(self) -> bytes:
        buf = bytearray(3)
        total_length = 0
        for c in self.certificate_list:
            cert_bytes = c.public_bytes(Encoding.DER)
            cert_bytes_length = len(cert_bytes)
            buf.extend(pack('>I', cert_bytes_length)[1:])
            total_length += 3
            buf.extend(cert_bytes)
            total_length += cert_bytes_length
        total_length_encoded = pack('>I', total_length)[1:]
        buf[:3] = total_length_encoded
        return bytes(buf)


@attrs(auto_attribs=True, slots=True)
class ServerKeyExchange(HandshakeMessageData):
    message_type = 12

    raw_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerKeyExchange':
        return ServerKeyExchange(raw_data=reader.read_bytes_to_end())

    def encode(self) -> bytes:
        return self.raw_data


class ServerHelloDone(HandshakeMessageData):
    message_type = 14

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerHelloDone':
        return ServerHelloDone()

    def encode(self) -> bytes:
        return b''


@attrs(auto_attribs=True, slots=True)
class ClientKeyExchange(HandshakeMessageData):
    message_type = 16

    raw_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'ClientKeyExchange':
        return ClientKeyExchange(raw_data=reader.read_bytes_to_end())

    def encode(self) -> bytes:
        return self.raw_data


@attrs(auto_attribs=True, slots=True)
class Finished(HandshakeMessageData):
    message_type = 20

    verify_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'Finished':
        return Finished(verify_data=reader.read_bytes_to_end())

    def encode(self) -> bytes:
        return self.verify_data


class HandshakeMessageType(EnumUInt8WithData):
    hello_request = (HelloRequest.message_type, HelloRequest)
    client_hello = (ClientHello.message_type, ClientHello)
    server_hello = (ServerHello.message_type, ServerHello)
    certificate = (PeerCertificate.message_type, PeerCertificate)
    server_key_exchange = (ServerKeyExchange.message_type, ServerKeyExchange)
    # certificate_request = 13
    server_hello_done = (ServerHelloDone.message_type, ServerHelloDone)
    # certificate_verify = 15
    client_key_exchange = (ClientKeyExchange.message_type, ClientKeyExchange)
    finished = (Finished.message_type, Finished)

    def __init__(self, value, data_type: Type[HandshakeMessageData]):
        super().__init__(value)
        self.data_type = data_type


@attrs(auto_attribs=True, slots=True)
class HandshakeMessage(ContentMessage):
    type = ContentType.handshake
    message_type: HandshakeMessageType
    data: HandshakeMessageData

    @classmethod
    def next_message_size(cls, data: Sequence[int]) -> Optional[int]:
        if len(data) < 4:
            return None
        message_byte_size_msb, message_byte_size_lsb = unpack_from('>BH', data, offset=1)
        message_byte_size = message_byte_size_msb << 16 | message_byte_size_lsb
        return 4 + message_byte_size

    @classmethod
    def decode(cls, reader: DataReader) -> 'HandshakeMessage':
        message_type = HandshakeMessageType.decode(reader)

        message_byte_size = reader.read_uint24()
        if reader.remaining_data_length != message_byte_size:
            raise RuntimeError(
                f"Did not receive all data - expected {message_byte_size} bytes, got {reader.remaining_data_length}"
            )
        return HandshakeMessage(
            message_type=message_type,
            data=message_type.data_type.decode(reader),
        )

    def encode(self) -> bytes:
        message_byte_data = self.data.encode()
        message_byte_size = len(message_byte_data)
        encoded_message_byte_size: bytes = pack('>I', message_byte_size)[1:]
        return self.message_type.encode() + encoded_message_byte_size + message_byte_data
