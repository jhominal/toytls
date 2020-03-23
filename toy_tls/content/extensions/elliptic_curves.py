from __future__ import generator_stop

from abc import abstractmethod, ABCMeta
from typing import Sequence, Generic, TypeVar

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, EllipticCurvePublicKey, \
    EllipticCurvePrivateKey, EllipticCurve, ECDH
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typing_extensions import Protocol

from toy_tls._data_reader import DataReader
from toy_tls._data_writer import DataWriter
from toy_tls.content.extensions import ExtensionData
from toy_tls.enum_with_data import EnumUInt16WithData


TPublicKey = TypeVar('TPublicKey')


class PrivateKey(Protocol[TPublicKey]):
    def public_key(self) -> TPublicKey:
        raise NotImplementedError


TPrivateKey = TypeVar('TPrivateKey', bound=PrivateKey)


class NamedCurveFunctions(Generic[TPublicKey, TPrivateKey], metaclass=ABCMeta):
    __slots__ = ()

    @property
    @abstractmethod
    def is_supported(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def load_public_key(self, data: bytes) -> TPublicKey:
        raise NotImplementedError

    @abstractmethod
    def generate_private_key(self) -> TPrivateKey:
        raise NotImplementedError

    @abstractmethod
    def execute_key_exchange(self, private_key: TPrivateKey, peer_public_key: TPublicKey) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def serialize_public_key(self, public_key: TPublicKey) -> bytes:
        raise NotImplementedError


@attrs(auto_attribs=True, slots=True)
class EllipticCurveFunctions(NamedCurveFunctions[EllipticCurvePublicKey, EllipticCurvePrivateKey]):
    curve: EllipticCurve = attrib(validator=instance_of(EllipticCurve))

    def is_supported(self) -> bool:
        return default_backend().elliptic_curve_supported(self.curve)

    def load_public_key(self, data: bytes) -> EllipticCurvePublicKey:
        return EllipticCurvePublicKey.from_encoded_point(curve=self.curve, data=data)

    def generate_private_key(self) -> EllipticCurvePrivateKey:
        return default_backend().generate_elliptic_curve_private_key(curve=self.curve)

    def execute_key_exchange(self, private_key: EllipticCurvePrivateKey, peer_public_key: EllipticCurvePublicKey) -> bytes:
        return private_key.exchange(algorithm=ECDH(), peer_public_key=peer_public_key)

    def serialize_public_key(self, public_key: EllipticCurvePublicKey) -> bytes:
        return public_key.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)


class X25519Functions(NamedCurveFunctions[X25519PublicKey, X25519PrivateKey]):
    def is_supported(self) -> bool:
        return default_backend().x25519_supported()

    def load_public_key(self, data: bytes) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(data=data)

    def generate_private_key(self) -> X25519PrivateKey:
        return default_backend().x25519_generate_key()

    def execute_key_exchange(self, private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
        return private_key.exchange(peer_public_key=peer_public_key)

    def serialize_public_key(self, public_key: X25519PublicKey) -> bytes:
        return public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


class X448Functions(NamedCurveFunctions[X448PublicKey, X448PrivateKey]):
    def is_supported(self) -> bool:
        return default_backend().x448_supported()

    def load_public_key(self, data: bytes) -> X448PublicKey:
        return X448PublicKey.from_public_bytes(data=data)

    def generate_private_key(self) -> X448PrivateKey:
        return default_backend().x448_generate_key()

    def execute_key_exchange(self, private_key: X448PrivateKey, peer_public_key: X448PublicKey) -> bytes:
        return private_key.exchange(peer_public_key=peer_public_key)

    def serialize_public_key(self, public_key: X448PublicKey) -> bytes:
        return public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


class NamedCurve(EnumUInt16WithData):
    secp256r1 = (23, EllipticCurveFunctions(SECP256R1()))
    secp384r1 = (24, EllipticCurveFunctions(SECP384R1()))
    secp521r1 = (25, EllipticCurveFunctions(SECP521R1()))
    x25519 = (29, X25519Functions())
    x448 = (30, X448Functions())

    def __init__(self, value, functions: NamedCurveFunctions):
        super().__init__(value, functions)
        self.functions = functions

    @property
    def supported(self):
        return self.functions.is_supported

    def load_public_key(self, data: bytes):
        return self.functions.load_public_key(data=data)

    def generate_private_key(self):
        return self.functions.generate_private_key()

    def execute_key_exchange(self, private_key: TPrivateKey, peer_public_key: TPublicKey) -> bytes:
        return self.functions.execute_key_exchange(private_key=private_key, peer_public_key=peer_public_key)

    def serialize_public_key(self, public_key: TPublicKey) -> bytes:
        return self.functions.serialize_public_key(public_key=public_key)


@attrs(auto_attribs=True, slots=True, frozen=True)
class NamedCurveList(ExtensionData):
    type = 10

    ALL = None

    supported_curves: Sequence[NamedCurve]

    @classmethod
    def decode(cls, reader: DataReader) -> 'NamedCurveList':
        length = reader.read_uint16()
        return NamedCurveList(
            supported_curves=reader.limited(length).read_sequence(NamedCurve),
        )

    def encode(self, writer: DataWriter):
        with writer.length_uint16():
            for c in self.supported_curves:
                writer.write(c)


NamedCurveList.ALL = NamedCurveList(supported_curves=tuple((c for c in NamedCurve if c.supported)))
