from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Type, Tuple

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, HashAlgorithm

from toy_tls._data_reader import DataReader, SupportsDecode
from toy_tls.content.extensions.elliptic_curves import NamedCurve
from toy_tls.content.extensions.signature_algorithms import DigitalSignature
from toy_tls.encryption import EncryptionEngine
from toy_tls.encryption.aead_engine import ChaCha20Poly1305Engine, AESGCMEngine
from toy_tls.enum_with_data import EnumUInt16WithData, EnumUInt8WithData
from toy_tls.validation import bounded_bytes


class IncompatiblePublicKeyError(Exception):
    pass


class ClientKeyExchangeParameters(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'ClientKeyExchangeParameters':
        raise NotImplementedError

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError


@attrs(auto_attribs=True, slots=True)
class KeyExchangeResult:
    client_key_exchange_parameters: ClientKeyExchangeParameters = attrib(validator=instance_of(ClientKeyExchangeParameters))
    shared_secret: bytes = attrib(validator=instance_of(bytes))


class ServerKeyExchangeParameters(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def decode(cls, reader: DataReader) -> 'ServerKeyExchangeParameters':
        raise NotImplementedError

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def verify_signature(self, server_public_key, client_random: bytes, server_random: bytes):
        raise NotImplementedError

    @abstractmethod
    def execute_key_exchange(self) -> KeyExchangeResult:
        raise NotImplementedError


class EllipticCurveType(EnumUInt8WithData):
    named_curve = (3, NamedCurve)

    def __init__(self, value, parameter_type: Type[SupportsDecode]):
        super().__init__(value, parameter_type)
        self.parameter_type = parameter_type


@attrs(auto_attribs=True, slots=True)
class ServerECDHParameters(ServerKeyExchangeParameters):
    curve_type: EllipticCurveType
    curve_data: NamedCurve
    public_key_bytes: bytes = attrib(validator=bounded_bytes(max_length=0xFF))
    signature: DigitalSignature

    @classmethod
    def decode(cls, reader: DataReader) -> 'ServerECDHParameters':
        curve_type = EllipticCurveType.decode(reader)
        return ServerECDHParameters(
            curve_type=curve_type,
            curve_data=curve_type.parameter_type.decode(reader),
            public_key_bytes=reader.read_bytes(reader.read_byte()),
            signature=DigitalSignature.decode(reader),
        )

    def encode_params(self) -> bytes:
        buf = bytearray()
        buf.extend(self.curve_type.encode())
        buf.extend(self.curve_data.encode())
        buf.append(len(self.public_key_bytes))
        buf.extend(self.public_key_bytes)
        return bytes(buf)

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.encode_params())
        buf.extend(self.signature.encode())
        return bytes(buf)

    def verify_signature(self, server_public_key, client_random: bytes, server_random: bytes):
        buf = bytearray()
        buf.extend(client_random)
        buf.extend(server_random)
        buf.extend(self.encode_params())
        return self.signature.verify(public_key=server_public_key, data=bytes(buf))

    def execute_key_exchange(self) -> KeyExchangeResult:
        private_key = self.curve_data.generate_private_key()
        peer_public_key = self.curve_data.load_public_key(self.public_key_bytes)
        public_key_bytes = self.curve_data.serialize_public_key(private_key.public_key())
        return KeyExchangeResult(
            client_key_exchange_parameters=ClientECDHParameters(public_key_bytes=public_key_bytes),
            shared_secret=self.curve_data.execute_key_exchange(private_key=private_key, peer_public_key=peer_public_key),
        )


@attrs(auto_attribs=True, slots=True)
class ClientECDHParameters(ClientKeyExchangeParameters):
    public_key_bytes: bytes = attrib(validator=bounded_bytes(max_length=0xFF))

    @classmethod
    def decode(cls, reader: DataReader) -> 'ClientECDHParameters':
        bytes_len = reader.read_byte()
        return ClientECDHParameters(public_key_bytes=reader.read_bytes(bytes_len))

    def encode(self) -> bytes:
        buf = bytearray()
        buf.append(len(self.public_key_bytes))
        buf.extend(self.public_key_bytes)
        return bytes(buf)


class KeyExchangeAlgorithm(Enum):
    ECDHE_ECDSA = ((EllipticCurvePublicKey, X25519PublicKey, X448PublicKey), ServerECDHParameters)
    ECDHE_RSA = ((RSAPublicKey,), ServerECDHParameters)

    def __init__(self, public_key_type: Tuple[Type, ...], server_parameters_type: Type[ServerKeyExchangeParameters]):
        self.public_key_types = public_key_type
        self.server_parameters_type = server_parameters_type

    def validate_public_key(self, public_key):
        if not isinstance(public_key, self.public_key_types):
            raise IncompatiblePublicKeyError(
                f'Public key has type {type(public_key)} but cipher suite requires one of {self.public_key_types}'
            )
        if isinstance(public_key, EllipticCurvePublicKey):
            if not isinstance(public_key.curve, (SECP256R1, SECP384R1, SECP521R1)):
                raise IncompatiblePublicKeyError(
                    f'Public key is on unsupported curve {public_key.curve.name}.'
                )


class CipherSuite(EnumUInt16WithData):

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = (0xC02B, KeyExchangeAlgorithm.ECDHE_ECDSA, AESGCMEngine(16), SHA256())
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = (0xC02C, KeyExchangeAlgorithm.ECDHE_ECDSA, AESGCMEngine(32), SHA384())
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = (0xC02F, KeyExchangeAlgorithm.ECDHE_RSA, AESGCMEngine(16), SHA256())
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = (0xC030, KeyExchangeAlgorithm.ECDHE_RSA, AESGCMEngine(32), SHA384())
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = (0xCCA8, KeyExchangeAlgorithm.ECDHE_RSA, ChaCha20Poly1305Engine(), SHA256())
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = (0xCCA9, KeyExchangeAlgorithm.ECDHE_ECDSA, ChaCha20Poly1305Engine(), SHA256())

    def __init__(self, value, key_exchange_algorithm: KeyExchangeAlgorithm, encryption_engine: EncryptionEngine, hash_for_prf: HashAlgorithm):
        super().__init__(value, key_exchange_algorithm, encryption_engine, hash_for_prf)
        self.key_exchange_algorithm = key_exchange_algorithm
        self.encryption_engine = encryption_engine
        self.hash_for_prf = hash_for_prf

    def validate_public_key(self, public_key):
        return self.key_exchange_algorithm.validate_public_key(public_key)

    def decode_server_parameters(self, reader: DataReader) -> ServerKeyExchangeParameters:
        return self.key_exchange_algorithm.server_parameters_type.decode(reader)
