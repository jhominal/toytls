from __future__ import generator_stop

from abc import abstractmethod
from typing import Sequence, ClassVar, Type, Generic, TypeVar, Optional

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDSA
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512, HashAlgorithm

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt16WithData, ExtensibleEnum


TPublicKey = TypeVar('TPublicKey')
TPrivateKey = TypeVar('TPrivateKey')


class SignatureFunctions(Generic[TPublicKey, TPrivateKey]):
    __slots__ = ()

    public_key_type: ClassVar[Type[TPublicKey]]
    private_key_type: ClassVar[Type[TPrivateKey]]

    def verify(self, public_key: TPublicKey, signature: bytes, data: bytes):
        if not isinstance(public_key, self.public_key_type):
            raise ValueError(
                f'Expected private_key of type {self.public_key_type.__name__} but got {type(public_key).__name__}'
            )
        return self._verify(public_key=public_key, signature=signature, data=data)

    def sign(self, private_key: TPrivateKey, data: bytes) -> bytes:
        if not isinstance(private_key, self.private_key_type):
            raise ValueError(
                f'Expected private_key of type {self.private_key_type.__name__} but got {type(private_key).__name__}'
            )
        return self._sign(private_key=private_key, data=data)

    @abstractmethod
    def _verify(self, public_key: TPublicKey, signature: bytes, data: bytes):
        raise NotImplementedError

    @abstractmethod
    def _sign(self, private_key: TPrivateKey, data: bytes) -> bytes:
        raise NotImplementedError


@attrs(auto_attribs=True, frozen=True)
class RSASignatureFunctions(SignatureFunctions[RSAPublicKey, RSAPrivateKey]):
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    public_key_type = RSAPublicKey
    private_key_type = RSAPrivateKey

    def _verify(self, public_key: RSAPublicKey, signature: bytes, data: bytes):
        return public_key.verify(signature=signature, data=data, padding=PKCS1v15(), algorithm=self.hash)

    def _sign(self, private_key: RSAPrivateKey, data: bytes) -> bytes:
        return private_key.sign(data=data, padding=PKCS1v15(), algorithm=self.hash)


@attrs(auto_attribs=True, frozen=True)
class DSSSignatureFunctions(SignatureFunctions[DSAPublicKey, DSAPrivateKey]):
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    public_key_type = DSAPublicKey
    private_key_type = DSAPrivateKey

    def _verify(self, public_key: DSAPublicKey, signature: bytes, data: bytes):
        return public_key.verify(signature=signature, data=data, algorithm=self.hash)

    def _sign(self, private_key: DSAPrivateKey, data: bytes) -> bytes:
        return private_key.sign(data=data, algorithm=self.hash)


@attrs(auto_attribs=True, frozen=True)
class ECDSASignatureFunctions(SignatureFunctions[EllipticCurvePublicKey, EllipticCurvePrivateKey]):
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    public_key_type = EllipticCurvePublicKey
    private_key_type = EllipticCurvePrivateKey

    def _verify(self, public_key: EllipticCurvePublicKey, signature: bytes, data: bytes):
        return public_key.verify(signature=signature, data=data, signature_algorithm=ECDSA(self.hash))

    def _sign(self, private_key: EllipticCurvePrivateKey, data: bytes) -> bytes:
        return private_key.sign(data=data, signature_algorithm=ECDSA(self.hash))


class Ed25519SignatureFunctions(SignatureFunctions[Ed25519PublicKey, Ed25519PrivateKey]):
    public_key_type = Ed25519PublicKey
    private_key_type = Ed25519PrivateKey

    def _verify(self, public_key: Ed25519PublicKey, signature: bytes, data: bytes):
        return public_key.verify(signature=signature, data=data)

    def _sign(self, private_key: Ed25519PrivateKey, data: bytes) -> bytes:
        return private_key.sign(data)


class Ed448SignatureFunctions(SignatureFunctions[Ed448PublicKey, Ed448PrivateKey]):
    public_key_type = Ed448PublicKey
    private_key_type = Ed448PrivateKey

    def _verify(self, public_key: Ed448PublicKey, signature: bytes, data: bytes):
        return public_key.verify(signature=signature, data=data)

    def _sign(self, private_key: Ed448PrivateKey, data: bytes) -> bytes:
        return private_key.sign(data)


class SignatureScheme(EnumUInt16WithData, ExtensibleEnum):
    rsa_pkcs1_sha1 = (0x0201, RSASignatureFunctions(hash=SHA1()))
    dss_sha1 = (0x0202, DSSSignatureFunctions(hash=SHA1()))
    ecdsa_sha1 = (0x0203, ECDSASignatureFunctions(hash=SHA1()))
    rsa_pkcs1_sha224 = (0x0301, RSASignatureFunctions(hash=SHA224()))
    dss_sha224 = (0x0302, DSSSignatureFunctions(hash=SHA224()))
    ecdsa_sha224 = (0x0303, ECDSASignatureFunctions(hash=SHA224()))
    rsa_pkcs1_sha256 = (0x0401, RSASignatureFunctions(hash=SHA256()))
    dss_sha256 = (0x0402, DSSSignatureFunctions(hash=SHA256()))
    ecdsa_sha256 = (0x0403, ECDSASignatureFunctions(hash=SHA256()))
    rsa_pkcs1_sha384 = (0x0501, RSASignatureFunctions(hash=SHA384()))
    dss_sha384 = (0x0502, DSSSignatureFunctions(hash=SHA384()))
    ecdsa_sha384 = (0x0503, ECDSASignatureFunctions(hash=SHA384()))
    rsa_pkcs1_sha512 = (0x0601, RSASignatureFunctions(hash=SHA512()))
    dss_sha512 = (0x0602, DSSSignatureFunctions(hash=SHA512()))
    ecdsa_sha512 = (0x0603, ECDSASignatureFunctions(hash=SHA512()))
    ed25519 = (0x0807, Ed25519SignatureFunctions())
    ed448 = (0x0808, Ed448SignatureFunctions())

    def __init__(
        self,
        value: int,
        signature_functions: Optional[SignatureFunctions] = None,
    ):
        super().__init__(value, signature_functions)
        self.signature_functions = signature_functions

    def verify(self, public_key, signature: bytes, data: bytes):
        return self.signature_functions.verify(public_key=public_key, signature=signature, data=data)


@attrs(auto_attribs=True, slots=True)
class DigitalSignature:
    scheme: SignatureScheme
    signature: bytes

    @classmethod
    def decode(cls, reader: DataReader) -> 'DigitalSignature':
        scheme = SignatureScheme.decode(reader)
        signature_length = reader.read_uint16()
        return DigitalSignature(
            scheme=scheme,
            signature=reader.read_bytes(signature_length),
        )

    def encode(self, writer: DataWriter):
        writer.write(self.scheme)
        with writer.length_uint16():
            writer.write_bytes(self.signature)

    def verify(self, public_key, data: bytes):
        self.scheme.verify(public_key=public_key, signature=self.signature, data=data)


@attrs(auto_attribs=True, slots=True, frozen=True)
class SupportedSignatureAlgorithms(ExtensionData):
    type = 13
    algorithms: Sequence[SignatureScheme]

    @classmethod
    def decode(cls, reader: DataReader) -> 'SupportedSignatureAlgorithms':
        algorithms_byte_len = reader.read_uint16()
        algorithms = reader.limited(algorithms_byte_len).read_sequence(SignatureScheme)
        return SupportedSignatureAlgorithms(algorithms)

    def encode(self, writer: DataWriter):
        with writer.length_uint16():
            for alg in self.algorithms:
                writer.write(alg)
