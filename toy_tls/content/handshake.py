from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from struct import unpack_from
from typing import ClassVar, Sequence, Type, Optional, List, TypeVar, Union, Tuple

from asn1crypto.x509 import Name
from attr import attrs, attrib
from attr.validators import instance_of, deep_iterable
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_der_x509_certificate

from toy_tls._cipher_suites import CipherSuite
from toy_tls._common import ProtocolVersion, CompressionMethod
from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content import ContentType, ContentMessage
from toy_tls.content.extensions import ExtensionData, UnknownExtension
from toy_tls.content.extensions.ec_points_formats import EllipticCurvePointFormatList
from toy_tls.content.extensions.elliptic_curves import NamedCurveList
from toy_tls.content.extensions.encrypt_then_mac import EncryptThenMac
from toy_tls.content.extensions.renegotiation_info import RenegotiationInfo
from toy_tls.content.extensions.server_name import ServerNameList
from toy_tls.content.extensions.signature_algorithms import SupportedSignatureAlgorithms, SignatureScheme, \
    DigitalSignature
from toy_tls.enum_with_data import EnumUInt8WithData, EnumUInt16WithData, ExtensibleEnum
from toy_tls.validation import fixed_bytes, bounded_bytes

TExtensionData = TypeVar('TExtensionData', bound=ExtensionData)


class HandshakeMessageData(metaclass=ABCMeta):
    __slots__ = ()
    message_type: ClassVar[int]

    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'HandshakeMessageData':
        raise NotImplementedError

    @abstractmethod
    def encode(self, writer: DataWriter):
        raise NotImplementedError


# Sent by the server to initiate a renegotiation
@attrs(auto_attribs=True, slots=True)
class HelloRequest(HandshakeMessageData):
    message_type = 0

    @classmethod
    def decode(cls, reader: DataReader) -> 'HelloRequest':
        return HelloRequest()

    def encode(self, writer: DataWriter):
        pass


class ExtensionType(EnumUInt16WithData, ExtensibleEnum):
    server_name = (ServerNameList.type, ServerNameList)
    elliptic_curves = (NamedCurveList.type, NamedCurveList)
    ec_points_formats = (EllipticCurvePointFormatList.type, EllipticCurvePointFormatList)
    signature_algorithms = (SupportedSignatureAlgorithms.type, SupportedSignatureAlgorithms)
    encrypt_then_mac = (EncryptThenMac.type, EncryptThenMac)
    renegotiation_info = (RenegotiationInfo.type, RenegotiationInfo)

    def __init__(self, value, data_type: Type[ExtensionData] = UnknownExtension):
        super().__init__(value, data_type)
        self.data_type = data_type


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

    def encode(self, writer: DataWriter):
        writer.write(self.type)

        with writer.length_uint16():
            writer.write(self.data)


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

    def encode(self, writer: DataWriter):
        writer.write(self.client_version)
        writer.write_bytes(self.random)

        with writer.length_byte():
            writer.write_bytes(self.session_id)

        with writer.length_uint16():
            for cs in self.cipher_suites:
                writer.write(cs)

        with writer.length_byte():
            for cm in self.compression_methods:
                writer.write(cm)

        if len(self.extensions) > 0:
            with writer.length_uint16():
                for extension in self.extensions:
                    writer.write(extension)


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

    def encode(self, writer: DataWriter):
        writer.write(self.server_version)
        writer.write_bytes(self.random)

        with writer.length_byte():
            writer.write_bytes(self.session_id)

        writer.write(self.cipher_suite)
        writer.write(self.compression_method)

        if len(self.extensions) > 0:
            with writer.length_uint16():
                for extension in self.extensions:
                    writer.write(extension)

    def find_extension(self, extension_data_type: Type[TExtensionData]) -> Optional[TExtensionData]:
        for extension in self.extensions:
            if extension.type.value == extension_data_type.type:
                return extension.data
        return None


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

    def encode(self, writer: DataWriter):
        with writer.length_uint24():
            for c in self.certificate_list:
                with writer.length_uint24():
                    writer.write_bytes(c.public_bytes(Encoding.DER))


@attrs(auto_attribs=True, slots=True)
class ServerKeyExchange(HandshakeMessageData):
    message_type = 12

    raw_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerKeyExchange':
        return ServerKeyExchange(raw_data=reader.read_bytes_to_end())

    def encode(self, writer: DataWriter):
        writer.write_bytes(self.raw_data)


class ClientCertificateType(EnumUInt8WithData, ExtensibleEnum):
    rsa_sign = (1, RSAPublicKey)
    dss_sign = (2, DSAPublicKey)
    rsa_fixed_dh = 3
    dss_fixed_dh = 4
    rsa_ephemeral_dh_RESERVED = 5
    dss_ephemeral_dh_RESERVED = 6
    fortezza_dms_RESERVED = 20
    ecdsa_sign = (64, (EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey))
    rsa_fixed_ecdh = 65
    ecdsa_fixed_ecdh = 66

    def __init__(self, value: int, public_key_types: Union[None, Type, Tuple[Type, ...]] = None):
        super().__init__(value, public_key_types)
        self._public_key_types = public_key_types

    def is_compatible_with(self, public_key):
        if self._public_key_types is None:
            return False
        return isinstance(public_key, self._public_key_types)


@attrs(auto_attribs=True, slots=True)
class CertificateRequest(HandshakeMessageData):
    message_type = 13

    certificate_types: Sequence[ClientCertificateType]
    supported_signature_algorithms: Sequence[SignatureScheme]
    certificate_authorities: Sequence[Name]

    @classmethod
    def decode(cls, reader: DataReader) -> 'CertificateRequest':
        certificate_types = reader.limited(reader.read_byte()).read_sequence(ClientCertificateType)
        supported_signature_algorithms = reader.limited(reader.read_uint16()).read_sequence(SignatureScheme)
        certificate_authorities = []
        ca_reader = reader.limited(reader.read_uint16())
        while not ca_reader.at_end_of_data:
            name_bytes = ca_reader.read_bytes(ca_reader.read_uint16())
            certificate_authorities.append(Name.load(name_bytes))

        return CertificateRequest(
            certificate_types=certificate_types,
            supported_signature_algorithms=supported_signature_algorithms,
            certificate_authorities=certificate_authorities,
        )

    def encode(self, writer: DataWriter):
        with writer.length_byte():
            for t in self.certificate_types:
                writer.write(t)
        with writer.length_uint16():
            for s in self.supported_signature_algorithms:
                writer.write(s)
        with writer.length_uint16():
            for ca in self.certificate_authorities:
                with writer.length_uint16():
                    writer.write_bytes(ca.dump())


class ServerHelloDone(HandshakeMessageData):
    message_type = 14

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerHelloDone':
        return ServerHelloDone()

    def encode(self, writer: DataWriter):
        pass


@attrs(auto_attribs=True, slots=True)
class CertificateVerify(HandshakeMessageData):
    message_type = 15

    signature: DigitalSignature

    @classmethod
    def decode(cls, reader: DataReader) -> 'CertificateVerify':
        return CertificateVerify(signature=DigitalSignature.decode(reader=reader))

    def encode(self, writer: DataWriter):
        self.signature.encode(writer=writer)


@attrs(auto_attribs=True, slots=True)
class ClientKeyExchange(HandshakeMessageData):
    message_type = 16

    raw_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'ClientKeyExchange':
        return ClientKeyExchange(raw_data=reader.read_bytes_to_end())

    def encode(self, writer: DataWriter):
        writer.write_bytes(self.raw_data)


@attrs(auto_attribs=True, slots=True)
class Finished(HandshakeMessageData):
    message_type = 20

    verify_data: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'Finished':
        return Finished(verify_data=reader.read_bytes_to_end())

    def encode(self, writer: DataWriter):
        writer.write_bytes(self.verify_data)


class HandshakeMessageType(EnumUInt8WithData):
    hello_request = (HelloRequest.message_type, HelloRequest)
    client_hello = (ClientHello.message_type, ClientHello)
    server_hello = (ServerHello.message_type, ServerHello)
    certificate = (PeerCertificate.message_type, PeerCertificate)
    server_key_exchange = (ServerKeyExchange.message_type, ServerKeyExchange)
    certificate_request = (CertificateRequest.message_type, CertificateRequest)
    server_hello_done = (ServerHelloDone.message_type, ServerHelloDone)
    certificate_verify = (CertificateVerify.message_type, CertificateVerify)
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

    def encode(self, writer: DataWriter):
        writer.write(self.message_type)
        with writer.length_uint24():
            writer.write(self.data)
