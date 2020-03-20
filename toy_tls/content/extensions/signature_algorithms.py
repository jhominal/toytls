from __future__ import generator_stop

from abc import ABCMeta, abstractmethod
from functools import partial
from struct import pack
from typing import Sequence

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from typing_extensions import Protocol

from toy_tls._data_reader import DataReader
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt16WithData


class Signer(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError()


class SignerFactory(Protocol):
    def __call__(self, private_key) -> Signer:
        raise NotImplementedError()


class Verifier(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def verify(self, data: bytes, signature: bytes):
        raise NotImplementedError()


class VerifierFactory(Protocol):
    def __call__(self, public_key) -> Verifier:
        raise NotImplementedError()


@attrs(auto_attribs=True, frozen=True)
class RSASigner(Signer):
    private_key: RSAPrivateKey = attrib(validator=instance_of(RSAPrivateKey))
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data=data, padding=PKCS1v15(), algorithm=self.hash)


@attrs(auto_attribs=True, frozen=True)
class RSAVerifier(Verifier):
    public_key: RSAPublicKey = attrib(validator=instance_of(RSAPublicKey))
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    def verify(self, signature:bytes, data: bytes):
        return self.public_key.verify(signature=signature, data=data, padding=PKCS1v15(), algorithm=self.hash)


@attrs(auto_attribs=True, frozen=True)
class ECDSASigner(Signer):
    private_key: EllipticCurvePrivateKey = attrib(validator=instance_of(EllipticCurvePrivateKey))
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data=data, signature_algorithm=ECDSA(self.hash))


@attrs(auto_attribs=True, frozen=True)
class ECDSAVerifier(Verifier):
    public_key: EllipticCurvePublicKey = attrib(validator=instance_of(EllipticCurvePublicKey))
    hash: HashAlgorithm = attrib(validator=instance_of(HashAlgorithm))

    def verify(self, signature: bytes, data: bytes):
        return self.public_key.verify(signature=signature, data=data, signature_algorithm=ECDSA(self.hash))


@attrs(auto_attribs=True, frozen=True)
class Ed25519Signer(Signer):
    private_key: Ed25519PrivateKey = attrib(validator=instance_of(Ed25519PrivateKey))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


@attrs(auto_attribs=True, frozen=True)
class Ed25519Verifier(Verifier):
    public_key: Ed25519PublicKey = attrib(validator=instance_of(Ed25519PublicKey))

    def verify(self, signature: bytes, data: bytes):
        return self.public_key.verify(signature=signature, data=data)


@attrs(auto_attribs=True, frozen=True)
class Ed448Signer(Signer):
    private_key: Ed448PrivateKey = attrib(validator=instance_of(Ed448PrivateKey))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


@attrs(auto_attribs=True, frozen=True)
class Ed448Verifier(Verifier):
    public_key: Ed448PublicKey = attrib(validator=instance_of(Ed448PublicKey))

    def verify(self, signature: bytes, data: bytes):
        return self.public_key.verify(signature=signature, data=data)


class SignatureScheme(EnumUInt16WithData):
    rsa_pkcs1_sha1 = (0x0201, partial(RSASigner, hash=SHA1()), partial(RSAVerifier, hash=SHA1()))
    ecdsa_sha1 = (0x0203, partial(ECDSASigner, hash=SHA1()), partial(ECDSAVerifier, hash=SHA1()))
    rsa_pkcs1_sha256 = (0x0401, partial(RSASigner, hash=SHA256()), partial(RSAVerifier, hash=SHA256()))
    ecdsa_secp256r1_sha256 = (0x0403, partial(ECDSASigner, hash=SHA256()), partial(ECDSAVerifier, hash=SHA256()))
    rsa_pkcs1_sha384 = (0x0501, partial(RSASigner, hash=SHA384()), partial(RSAVerifier, hash=SHA384()))
    ecdsa_secp384r1_sha384 = (0x0503, partial(ECDSASigner, hash=SHA384()), partial(ECDSAVerifier, hash=SHA384()))
    rsa_pkcs1_sha512 = (0x0601, partial(RSASigner, hash=SHA512()), partial(RSAVerifier, hash=SHA512()))
    ecdsa_secp521r1_sha512 = (0x0603, partial(ECDSASigner, hash=SHA512()), partial(ECDSAVerifier, hash=SHA512()))
    ed25519 = (0x0807, Ed25519Signer, Ed25519Verifier)
    ed448 = (0x0808, Ed448Signer, Ed448Verifier)

    def __init__(self, value: int, signer_factory: SignerFactory, verifier_factory: VerifierFactory):
        super().__init__(value, signer_factory, verifier_factory)
        self.signer_factory = signer_factory
        self.verifier_factory = verifier_factory


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

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.scheme.encode())
        buf.extend(pack('>H', len(self.signature)))
        buf.extend(self.signature)
        return bytes(buf)

    def verify(self, public_key, data: bytes):
        self.scheme.verifier_factory(public_key=public_key).verify(signature=self.signature, data=data)


@attrs(auto_attribs=True, slots=True, frozen=True)
class SupportedSignatureAlgorithms(ExtensionData):
    type = 13
    algorithms: Sequence[SignatureScheme]

    @classmethod
    def decode(cls, reader: DataReader) -> 'SupportedSignatureAlgorithms':
        algorithms_byte_len = reader.read_uint16()
        algorithms = reader.limited(algorithms_byte_len).read_sequence(SignatureScheme)
        return SupportedSignatureAlgorithms(algorithms)

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(pack('>H', len(self.algorithms) * 2))

        for alg in self.algorithms:
            buf.extend(alg.encode())

        return bytes(buf)
