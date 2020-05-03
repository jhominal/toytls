from __future__ import generator_stop

from enum import Flag, auto, Enum
from typing import Optional, Any, Protocol, BinaryIO, Iterable

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate, Certificate

from toy_tls.certificate import AnyPrivateKey, CertificateWithPrivateKey
from toy_tls.enum_with_data import ExtensibleEnum


class PemLoadFunction(Protocol):
    def __call__(self, data: bytes, password: Optional[bytes]) -> Any:
        raise NotImplementedError


def _load_private_key(data: bytes, password: Optional[bytes]) -> AnyPrivateKey:
    return load_pem_private_key(data=data, password=password, backend=default_backend())


def _load_certificate(data: bytes, password: Optional[bytes]) -> Certificate:
    if password is not None:
        raise RuntimeError('Certificates in PEM are not encrypted.')
    return load_pem_x509_certificate(data=data, backend=default_backend())


class EncryptionStatus(Flag):
    Unencrypted = auto()
    Encrypted = auto()
    Either = Unencrypted | Encrypted

    def includes(self, status: 'EncryptionStatus'):
        return self & status == status != EncryptionStatus(0)


class CryptoObjectType(Enum):
    Unknown = auto()
    PrivateKey = auto()
    Certificate = auto()


class PemObjectType(ExtensibleEnum):
    PrivateKey_PKCS8 = ("PRIVATE KEY", EncryptionStatus.Unencrypted, _load_private_key, CryptoObjectType.PrivateKey)
    PrivateKey_PKCS8_ENC = ("ENCRYPTED PRIVATE KEY", EncryptionStatus.Encrypted, _load_private_key, CryptoObjectType.PrivateKey)
    PrivateKey_PKCS1 = ("RSA PRIVATE KEY", EncryptionStatus.Either, _load_private_key, CryptoObjectType.PrivateKey)
    Certificate = ("CERTIFICATE", EncryptionStatus.Unencrypted, _load_certificate, CryptoObjectType.Certificate)

    def __init__(
        self,
        value: str,
        encryption_support: EncryptionStatus = EncryptionStatus(0),
        load_function: Optional[PemLoadFunction] = None,
        object_type: CryptoObjectType = CryptoObjectType.Unknown,
    ):
        super().__init__(value, encryption_support, load_function, object_type)
        self._header = value
        self._encryption_support = encryption_support
        self._load_function = load_function
        self.object_type = object_type

    def load(self, data: bytes, password: Optional[bytes] = None):
        if self._load_function is None:
            raise RuntimeError(f'PEM objects of type "{self._header}" cannot be loaded.')
        if password is None and not self._encryption_support.includes(EncryptionStatus.Unencrypted):
            raise RuntimeError(f'PEM objects of type "{self._header}" are always encrypted.')
        if password is not None and not self._encryption_support.includes(EncryptionStatus.Encrypted):
            raise RuntimeError(f'PEM objects of type "{self._header}" are never encrypted.')
        return self._load_function(data=data, password=password)


@attrs(auto_attribs=True, slots=True)
class PemObject:
    data: bytes = attrib(validator=instance_of(bytes))
    pem_type: PemObjectType = attrib(validator=instance_of(PemObjectType))
    _loaded_object: Any = attrib(init=False, default=None)

    @property
    def object_type(self) -> CryptoObjectType:
        return self.pem_type.object_type

    def load(self, password: Optional[bytes] = None):
        self._loaded_object = self.pem_type.load(data=self.data, password=password)

    @property
    def loaded_object(self) -> Any:
        if self._loaded_object is None:
            raise RuntimeError('The object has not been loaded yet.')
        return self._loaded_object


class PemObjectBuilder:
    @staticmethod
    def match_first_line(line: bytes):
        return line.startswith(b'-----BEGIN ')

    def __init__(self, first_line: bytes):
        self.name = first_line[11:first_line.index(b'-----', 11)].decode('ascii')
        self._last_line = first_line.replace(b'BEGIN', b'END')
        self.pem_type = PemObjectType(self.name)
        self._lines = [first_line]
        self.finished = False

    def append(self, line: bytes):
        if self.finished:
            raise RuntimeError('Cannot continue appending to object builder as it already has an END line.')
        self._lines.append(line)
        if line.startswith(self._last_line):
            self.finished = True

    def build(self) -> PemObject:
        return PemObject(data=b''.join(self._lines), pem_type=self.pem_type)


def read_pem_objects(f: BinaryIO) -> Iterable[PemObject]:
    current_object_builder: Optional[PemObjectBuilder] = None
    for line in f:
        if current_object_builder is not None:
            current_object_builder.append(line)
            if current_object_builder.finished:
                yield current_object_builder.build()
                current_object_builder = None
        elif PemObjectBuilder.match_first_line(line):
            current_object_builder = PemObjectBuilder(first_line=line)


def load_cert_and_key(
    cert_file: BinaryIO,
    key_file: Optional[BinaryIO],
    key_password: Optional[bytes],
) -> CertificateWithPrivateKey:
    private_key_object: Optional[PemObject] = None
    certificate_object: Optional[PemObject] = None
    if key_file is not None:
        for key_file_object in read_pem_objects(key_file):
            if key_file_object.object_type == CryptoObjectType.PrivateKey:
                private_key_object = key_file_object
                break

    for cert_file_object in read_pem_objects(cert_file):
        if certificate_object is None and cert_file_object.object_type == CryptoObjectType.Certificate:
            certificate_object = cert_file_object
        elif private_key_object is None and cert_file_object.object_type == CryptoObjectType.PrivateKey:
            private_key_object = cert_file_object

    if certificate_object is None:
        raise RuntimeError('Certificate object not found in cert file.')
    if private_key_object is None:
        raise RuntimeError('Private Key object not found in either cert file or key file.')

    certificate_object.load()
    private_key_object.load(password=key_password)

    return CertificateWithPrivateKey(
        certificate=certificate_object.loaded_object,
        private_key=private_key_object.loaded_object,
    )
