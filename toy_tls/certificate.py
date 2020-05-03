from __future__ import generator_stop

from enum import Flag, auto
from operator import methodcaller
from typing import Union, Type, Callable, Any

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate

from toy_tls.enum_with_data import ExtensibleEnum

AnyPrivateKey = Union[
    RSAPrivateKey, DSAPrivateKey, EllipticCurvePrivateKey,
    Ed25519PrivateKey, X25519PrivateKey,
    Ed448PrivateKey, X448PrivateKey,
]

AnyPublicKey = Union[
    RSAPublicKey, DSAPublicKey, EllipticCurvePublicKey,
    Ed25519PublicKey, X25519PublicKey,
    Ed448PublicKey, X448PublicKey,
]


class KeyPairValidationError(Exception):
    pass


class CryptoCapability(Flag):
    Signature = auto()
    Encryption = auto()
    KeyExchange = auto()

    def includes(self, capability: 'CryptoCapability'):
        return self & capability == capability != CryptoCapability(0)


class KeyPairType(ExtensibleEnum):
    rsa = (RSAPrivateKey, CryptoCapability.Signature | CryptoCapability.Encryption, methodcaller('public_numbers'))
    dss = (DSAPrivateKey, CryptoCapability.Signature, methodcaller('public_numbers'))
    ecdsa = (EllipticCurvePrivateKey, CryptoCapability.Signature | CryptoCapability.KeyExchange, methodcaller('public_numbers'))
    ed25519 = (Ed25519PrivateKey, CryptoCapability.Signature, methodcaller('public_bytes', encoding=Encoding.Raw, format=PublicFormat.Raw))
    x25519 = (X25519PrivateKey, CryptoCapability.KeyExchange, methodcaller('public_bytes', encoding=Encoding.Raw, format=PublicFormat.Raw))
    ed448 = (Ed448PrivateKey, CryptoCapability.Signature, methodcaller('public_bytes', encoding=Encoding.Raw, format=PublicFormat.Raw))
    x448 = (X448PrivateKey, CryptoCapability.KeyExchange, methodcaller('public_bytes', encoding=Encoding.Raw, format=PublicFormat.Raw))

    def __init__(
        self,
        value: Type[AnyPrivateKey],
        capabilities: CryptoCapability = CryptoCapability(0),
        comparison_key_getter: Callable[[AnyPublicKey], Any] = None,
    ):
        super().__init__(value, capabilities)
        self.capabilities = capabilities
        self.comparison_key_getter = comparison_key_getter

    @classmethod
    def _missing_(cls, value):
        for e in cls:
            if issubclass(value, e.value):
                return e
        return super()._missing_(value)


@attrs(auto_attribs=True, slots=True, frozen=True)
class CertificateWithPrivateKey:
    certificate: Certificate = attrib(validator=instance_of(Certificate))
    private_key: AnyPrivateKey

    def check_key_pair(self):
        if type(self.private_key.public_key()) != type(self.certificate.public_key()):
            raise KeyPairValidationError(
                f'Private key is a {type(self.private_key).__name__} but certificate '
                f'contains a {type(self.certificate.public_key()).__name__}.'
            )
        comparison_key_getter = KeyPairType(type(self.private_key)).comparison_key_getter
        if comparison_key_getter(self.private_key.public_key()) != comparison_key_getter(self.certificate.public_key()):
            raise KeyPairValidationError(
                'Private and public key do not belong to the same key pair.'
            )

    def supports_signature(self):
        return KeyPairType(type(self.private_key)).capabilities.includes(CryptoCapability.Signature)
