from __future__ import generator_stop

import logging
import os
from asyncio import StreamReader, StreamWriter
from enum import Enum, auto
from functools import partial
from typing import Type, TypeVar, Generic, Iterable, Sequence, Optional, List, Union

import cryptography.x509
from asn1crypto.x509 import Name
from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.x509 import Certificate

from toy_tls._cipher_suites import IncompatiblePublicKeyError
from toy_tls._common import ProtocolVersion
from toy_tls._data_reader import FullDataReader
from toy_tls._data_writer import DataWriter, SupportsEncode
from toy_tls._tls_record import TLSPlaintextRecord, TLSRecordEncoder, InitialTLSRecordEncoder, TLSRecordDecoder, \
    TLSRecordHeader, InitialTLSRecordDecoder
from toy_tls.certificate import CertificateWithPrivateKey
from toy_tls.content import ContentMessage, ContentType, ApplicationDataMessage
from toy_tls.content.alert import AlertMessage, AlertLevel, AlertDescription
from toy_tls.content.change_cipher_spec import ChangeCipherSpecMessage
from toy_tls.content.extensions.ec_points_formats import EllipticCurvePointFormatList
from toy_tls.content.extensions.elliptic_curves import NamedCurveList
from toy_tls.content.extensions.renegotiation_info import RenegotiationInfo
from toy_tls.content.extensions.server_name import ServerNameList
from toy_tls.content.extensions.signature_algorithms import SupportedSignatureAlgorithms, SignatureScheme, \
    DigitalSignature
from toy_tls.content.handshake import HandshakeMessage, ClientHello, Extension, CipherSuite, HandshakeMessageType, \
    HandshakeMessageData, ServerHello, PeerCertificate, ServerKeyExchange, CertificateRequest, ServerHelloDone, \
    ClientKeyExchange, Finished, HelloRequest, CertificateVerify
from toy_tls.validation import fixed_bytes

logger = logging.getLogger(__name__)


class TLSConnectionError(Exception):
    pass


class UnexpectedMessageError(TLSConnectionError):
    pass


@attrs(auto_attribs=True, slots=True, auto_exc=True)
class UnexpectedMessageContentTypeError(UnexpectedMessageError):
    message: str
    expected_type: ContentType
    actual_type: ContentType


@attrs(auto_attribs=True, slots=True, auto_exc=True)
class UnexpectedHandshakeMessageTypeError(UnexpectedMessageError):
    message: str
    expected_type: HandshakeMessageType
    actual_type: HandshakeMessageType


def get_encoded_bytes(value: SupportsEncode) -> bytes:
    writer = DataWriter()
    writer.write(value)
    return writer.to_bytes()


@attrs(auto_attribs=True, slots=True)
class TLSNegotiationState:
    client_random: bytes = attrib(init=False, validator=fixed_bytes(32))
    server_random: bytes = attrib(init=False, validator=fixed_bytes(32))
    cipher_suite: CipherSuite = attrib(init=False, validator=instance_of(CipherSuite))
    master_secret: bytes = attrib(init=False, validator=fixed_bytes(48))
    next_encoder: TLSRecordEncoder = attrib(init=False, validator=instance_of(TLSRecordEncoder))
    next_decoder: TLSRecordDecoder = attrib(init=False, validator=instance_of(TLSRecordDecoder))
    handshake_messages: List[HandshakeMessage] = attrib(init=False, factory=list)
    client_verify_data: bytes = attrib(init=False, validator=instance_of(bytes))
    server_verify_data: bytes = attrib(init=False, validator=instance_of(bytes))
    previous_state: Optional['TLSNegotiationState'] = attrib(default=None)

    def initialize_codec(self):
        engine = self.cipher_suite.encryption_engine
        key_material = self.cipher_suite.run_prf(
            secret=self.master_secret,
            label=b'key expansion',
            seed=self.server_random + self.client_random,
            length=engine.mac_key_length * 2 + engine.enc_key_length * 2 + engine.fixed_iv_length * 2,
        )
        client_write_mac_key, key_material = key_material[:engine.mac_key_length], key_material[engine.mac_key_length:]
        server_write_mac_key, key_material = key_material[:engine.mac_key_length], key_material[engine.mac_key_length:]
        client_write_key, key_material = key_material[:engine.enc_key_length], key_material[engine.enc_key_length:]
        server_write_key, key_material = key_material[:engine.enc_key_length], key_material[engine.enc_key_length:]
        client_write_iv, key_material = key_material[:engine.fixed_iv_length], key_material[engine.fixed_iv_length:]
        server_write_iv, key_material = key_material[:engine.fixed_iv_length], key_material[engine.fixed_iv_length:]

        if len(key_material) != 0:
            raise RuntimeError('Error while computing key material.')

        self.next_encoder = engine.encoder(
            mac_key=client_write_mac_key,
            enc_key=client_write_key,
            fixed_iv=client_write_iv,
        )
        self.next_decoder = engine.decoder(
            mac_key=server_write_mac_key,
            enc_key=server_write_key,
            fixed_iv=server_write_iv,
        )

    def encoded_handshake_messages(self) -> Iterable[bytes]:
        for message in self.handshake_messages:
            yield get_encoded_bytes(message)

    def compute_handshake_messages_hash(self) -> bytes:
        hash_context = Hash(algorithm=self.cipher_suite.hash_for_prf, backend=default_backend())
        for encoded_message in self.encoded_handshake_messages():
            hash_context.update(encoded_message)
        return hash_context.finalize()


HandshakeMessageLax = Union[HandshakeMessage, ChangeCipherSpecMessage]
TContentMessage = TypeVar('TContentMessage', bound=ContentMessage)
THandshakeMessageLax = TypeVar('THandshakeMessageLax', HandshakeMessage, ChangeCipherSpecMessage)
THandshakeMessageData = TypeVar('THandshakeMessageData', bound=HandshakeMessageData)


@attrs(auto_attribs=True, slots=True, frozen=True)
class ContentMessageDecoder(Generic[TContentMessage]):
    data_type: Type[TContentMessage]
    buffer: bytearray = attrib(init=False, factory=bytearray)

    def append_frame(self, frame: TLSPlaintextRecord):
        if frame.content_type != self.data_type.type:
            raise RuntimeError(
                f'Routing error: got TLS Frame of type {frame.content_type} but expected {self.data_type.type}'
            )
        self.buffer.extend(frame.data)

    def get_available_messages(self) -> Iterable[TContentMessage]:
        next_message_length = self.data_type.next_message_size(self.buffer)
        while next_message_length is not None and 0 < next_message_length <= len(self.buffer):
            next_message_bytes = bytes(self.buffer[:next_message_length])
            del self.buffer[:next_message_length]
            data_reader = FullDataReader(next_message_bytes)
            yield self.data_type.decode(data_reader)
            next_message_length = self.data_type.next_message_size(self.buffer)


@attrs(auto_attribs=True, slots=True, frozen=True)
class IncomingBuffer:
    change_cipher_spec: ContentMessageDecoder[ChangeCipherSpecMessage] = attrib(
        init=False,
        factory=partial(ContentMessageDecoder, ChangeCipherSpecMessage),
    )
    alert: ContentMessageDecoder[AlertMessage] = attrib(
        init=False,
        factory=partial(ContentMessageDecoder, AlertMessage),
    )
    handshake: ContentMessageDecoder[HandshakeMessage] = attrib(
        init=False,
        factory=partial(ContentMessageDecoder, HandshakeMessage),
    )
    application_data: ContentMessageDecoder = attrib(
        init=False,
        factory=partial(ContentMessageDecoder, ApplicationDataMessage),
    )

    def __getitem__(self, key: ContentType) -> ContentMessageDecoder:
        if key == ContentType.change_cipher_spec:
            return self.change_cipher_spec
        if key == ContentType.alert:
            return self.alert
        if key == ContentType.handshake:
            return self.handshake
        if key == ContentType.application_data:
            return self.application_data
        raise KeyError(key)

    def get_next_messages(self, tls_record: TLSPlaintextRecord) -> Iterable[ContentMessage]:
        buffer = self[tls_record.content_type]
        buffer.append_frame(tls_record)
        return buffer.get_available_messages()


class TLSConnectionStatus(Enum):
    initial_handshake = auto()
    established = auto()
    renegotiating = auto()
    closed = auto()


@attrs(auto_attribs=True, slots=True)
class TLSConnection:
    reader: StreamReader = attrib(kw_only=True)
    writer: StreamWriter = attrib(kw_only=True)
    hostname: str = attrib(kw_only=True)
    client_certificate: Optional[CertificateWithPrivateKey] = attrib(kw_only=True)
    certificate_chain: Sequence[Certificate] = attrib(kw_only=True, factory=list)

    protocol_version: ProtocolVersion = attrib(init=False, default=ProtocolVersion.TLS_1_2)

    encoder: TLSRecordEncoder = attrib(init=False, factory=InitialTLSRecordEncoder)
    next_sequence_number_to_send: int = attrib(init=False, default=0)
    decoder: TLSRecordDecoder = attrib(init=False, factory=InitialTLSRecordDecoder)
    next_expected_sequence_number: int = attrib(init=False, default=0)

    status: TLSConnectionStatus = attrib(init=False, default=TLSConnectionStatus.initial_handshake)
    secure_renegotiation: bool = attrib(init=False, default=False)
    negotiation_state: TLSNegotiationState = attrib(init=False, factory=TLSNegotiationState)

    buffer: IncomingBuffer = attrib(init=False, factory=IncomingBuffer)
    incoming_handshake_messages: List[HandshakeMessageLax] = attrib(init=False, factory=list)
    incoming_application_data: List[bytes] = attrib(init=False, factory=list)

    async def _send_fatal_alert(self, description: AlertDescription):
        return await self._send_message(
            AlertMessage(
                level=AlertLevel.fatal,
                description=description,
            )
        )

    async def close(self):
        await self._send_message(
            AlertMessage(
                level=AlertLevel.warning,
                description=AlertDescription.close_notify,
            )
        )
        self.writer.close()
        self.status = TLSConnectionStatus.closed

    async def _send_message(self, message: ContentMessage, protocol_version: Optional[ProtocolVersion] = None):
        if isinstance(message, HandshakeMessage):
            self.negotiation_state.handshake_messages.append(message)
        bytes_to_send = get_encoded_bytes(message)
        while len(bytes_to_send) > 0:
            record = TLSPlaintextRecord(
                content_type=message.type,
                protocol_version=protocol_version or self.protocol_version,
                data=bytes_to_send[0:1 << 14],
            )
            await self._send_tls_record(record)
            bytes_to_send = bytes_to_send[1 << 14:]

    async def _send_tls_record(self, record: TLSPlaintextRecord):
        writer = DataWriter()
        self.encoder.encode(
            sequence_number=self.next_sequence_number_to_send,
            record=record,
            writer=writer,
        )
        self.next_sequence_number_to_send += 1
        self.writer.write(writer.to_bytes())

    async def _wait_for_next_messages(self) -> Sequence[ContentMessage]:
        next_messages = []
        while len(next_messages) == 0:
            frame = await self._wait_for_tls_frame()
            next_messages.extend(self.buffer.get_next_messages(frame))
        return next_messages

    async def _wait_for_tls_frame(self) -> TLSPlaintextRecord:
        record_header = await self.reader.readexactly(5)
        parsed_header = TLSRecordHeader.decode(FullDataReader(record_header))
        record_bytes = await self.reader.readexactly(parsed_header.data_length)
        encrypted_data_reader = FullDataReader(record_bytes)
        decrypted_record = self.decoder.decode(
            expected_sequence_number=self.next_expected_sequence_number,
            header=parsed_header,
            data_reader=encrypted_data_reader,
        )
        self.next_expected_sequence_number += 1
        return decrypted_record

    async def do_initial_handshake(self):
        if self.status != TLSConnectionStatus.initial_handshake:
            raise RuntimeError('Invalid operation. Connection has already gone through initial handshake.')
        await self._execute_handshake()

    async def _check_for_renegotiation(self):
        if len(self.incoming_handshake_messages) == 0:
            return

        try:
            await self._expect_handshake_message_of_type(HelloRequest)
        except UnexpectedMessageError:
            return

        logger.info('Renegotiation initiated by server.')
        self.status = TLSConnectionStatus.renegotiating
        self.negotiation_state = TLSNegotiationState(previous_state=self.negotiation_state)

        await self._execute_handshake()

    async def _execute_handshake(self):
        self.negotiation_state.client_random = os.urandom(32)

        client_hello_extensions = [
            Extension.from_data(
                ServerNameList.create(self.hostname.encode('ascii'))
            ),
            Extension.from_data(
                NamedCurveList.ALL
            ),
            Extension.from_data(
                EllipticCurvePointFormatList(),
            ),
            Extension.from_data(
                SupportedSignatureAlgorithms(
                    algorithms=[
                        SignatureScheme.ed25519,
                        SignatureScheme.ed448,
                        SignatureScheme.ecdsa_sha512,
                        SignatureScheme.rsa_pkcs1_sha512,
                        SignatureScheme.ecdsa_sha384,
                        SignatureScheme.rsa_pkcs1_sha384,
                        SignatureScheme.ecdsa_sha256,
                        SignatureScheme.rsa_pkcs1_sha256,
                        SignatureScheme.ecdsa_sha1,
                        SignatureScheme.rsa_pkcs1_sha1,
                    ]
                )
            ),
        ]
        if self.status == TLSConnectionStatus.initial_handshake:
            client_hello_extensions.append(
                Extension.from_data(
                    RenegotiationInfo(data=b''),
                )
            )
        elif self.status == TLSConnectionStatus.renegotiating and self.secure_renegotiation:
            client_hello_extensions.append(
                Extension.from_data(
                    RenegotiationInfo(data=self.negotiation_state.previous_state.client_verify_data)
                )
            )

        client_hello = ClientHello(
            client_version=self.protocol_version,
            random=self.negotiation_state.client_random,
            cipher_suites=[
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            extensions=client_hello_extensions,
        )
        client_hello_message = HandshakeMessage(
            message_type=HandshakeMessageType.client_hello,
            data=client_hello,
        )
        if self.status == TLSConnectionStatus.initial_handshake:
            await self._send_message(client_hello_message, protocol_version=ProtocolVersion.TLS_1_0)
        else:
            await self._send_message(client_hello_message)

        server_hello = await self._expect_handshake_message_of_type(ServerHello)
        if server_hello.server_version < ProtocolVersion.TLS_1_2:
            await self._send_fatal_alert(description=AlertDescription.protocol_version)
            raise TLSConnectionError(
                f'Server Hello set TLS version {server_hello.server_version} '
                f'but {ProtocolVersion.TLS_1_2} was required.'
            )
        self.negotiation_state.server_random = server_hello.random
        self.negotiation_state.cipher_suite = server_hello.cipher_suite

        server_renegotiation_info = server_hello.find_extension(RenegotiationInfo)
        if self.status == TLSConnectionStatus.initial_handshake:
            if server_renegotiation_info is not None:
                self.secure_renegotiation = True
                if len(server_renegotiation_info.data) != 0:
                    raise TLSConnectionError('Found data in initial server-sent renegotiation object.')
        if self.status == TLSConnectionStatus.renegotiating:
            if server_renegotiation_info is None and self.secure_renegotiation:
                raise TLSConnectionError('Extension renegotiation_info missing from renegotiated ServerHello')
            elif server_renegotiation_info is not None:
                previous_verification_data = (
                    self.negotiation_state.previous_state.client_verify_data +
                    self.negotiation_state.previous_state.server_verify_data
                )
                if not constant_time.bytes_eq(server_renegotiation_info.data, previous_verification_data):
                    raise TLSConnectionError('Data in renegotiated ServerHello does not match verification values.')

        logger.debug(f'Negotiated cipher suite {server_hello.cipher_suite.name}')

        server_certificate_chain = await self._expect_handshake_message_of_type(PeerCertificate)
        server_certificate = server_certificate_chain.certificate_list[0]

        # TODO: certificate chain verification.

        try:
            self.negotiation_state.cipher_suite.validate_public_key(server_certificate.public_key())
        except IncompatiblePublicKeyError:
            await self._send_fatal_alert(AlertDescription.bad_certificate)
            raise TLSConnectionError(
                f'Server certificate public key is not compatible with chosen cipher suite '
                f'{self.negotiation_state.cipher_suite.name}'
            )

        server_key_exchange = await self._expect_handshake_message_of_type(ServerKeyExchange)
        data_reader = FullDataReader(server_key_exchange.raw_data)
        server_parameters = self.negotiation_state.cipher_suite.decode_server_parameters(data_reader)
        try:
            server_parameters.verify_signature(
                server_public_key=server_certificate.public_key(),
                client_random=self.negotiation_state.client_random,
                server_random=self.negotiation_state.server_random,
            )
        except InvalidSignature:
            await self._send_fatal_alert(AlertDescription.handshake_failure)
            raise TLSConnectionError(f'Invalid signature when validating ServerKeyExchange.') from None

        # OPTION ClientCert: Receive Certificate Request
        try:
            certificate_request = await self._expect_handshake_message_of_type(CertificateRequest)
            logger.info('Server requested client certificate.')
            logger.info(f'Accepted certificate types: {[f"{ct.name}: {ct.value}" for ct in certificate_request.certificate_types]}')
            logger.info(f'Accepted supported groups: {[f"{sa.name}: {sa.value:04x}" for sa in certificate_request.supported_signature_algorithms]}')
            logger.info(f'START Accepted CA names ({len(certificate_request.certificate_authorities)})')
            for ca in certificate_request.certificate_authorities:
                logger.info(ca.human_friendly)
            logger.info('END Accepted CA names')
        except UnexpectedMessageError:
            certificate_request = None

        await self._expect_handshake_message_of_type(ServerHelloDone)

        if certificate_request is not None:
            using_certificate = self._check_client_certificate_usable(certificate_request=certificate_request)
            certificate_list = []
            if using_certificate:
                certificate_list.append(self.client_certificate.certificate)
                certificate_list.extend(self.certificate_chain)
            await self._send_message(HandshakeMessage(
                message_type=HandshakeMessageType.certificate,
                data=PeerCertificate(certificate_list=certificate_list),
            ))
        else:
            using_certificate = False

        key_exchange = server_parameters.execute_key_exchange()

        self.negotiation_state.master_secret = self.negotiation_state.cipher_suite.run_prf(
            secret=key_exchange.shared_secret,
            label=b'master secret',
            seed=self.negotiation_state.client_random + self.negotiation_state.server_random,
            length=48,
        )

        await self._send_message(
            HandshakeMessage(
                message_type=HandshakeMessageType.client_key_exchange,
                data=ClientKeyExchange(raw_data=get_encoded_bytes(key_exchange.client_key_exchange_parameters)),
            )
        )

        del key_exchange  # Delete key_exchange to avoid persistence of key_exchange.shared_secret.

        # OPTION ClientCert: Send Client Certificate Verify
        if using_certificate and self.client_certificate.supports_signature():
            client_public_key = self.client_certificate.certificate.public_key()
            signature_scheme = next(
                signature_algorithm
                for signature_algorithm in certificate_request.supported_signature_algorithms
                if signature_algorithm.is_compatible_with(client_public_key)
            )
            await self._send_message(
                HandshakeMessage(
                    message_type=HandshakeMessageType.certificate_verify,
                    data=CertificateVerify(
                        signature=DigitalSignature.sign(
                            scheme=signature_scheme,
                            private_key=self.client_certificate.private_key,
                            data=b''.join(self.negotiation_state.encoded_handshake_messages()),
                        ),
                    )
                )
            )

        self.negotiation_state.initialize_codec()

        await self._send_message(ChangeCipherSpecMessage())
        self.encoder = self.negotiation_state.next_encoder
        self.next_sequence_number_to_send = 0

        self.negotiation_state.client_verify_data = self.negotiation_state.cipher_suite.run_prf(
            secret=self.negotiation_state.master_secret,
            label=b'client finished',
            seed=self.negotiation_state.compute_handshake_messages_hash(),
            length=12,
        )
        await self._send_message(
            HandshakeMessage(
                message_type=HandshakeMessageType.finished,
                data=Finished(verify_data=self.negotiation_state.client_verify_data),
            ),
        )

        await self._expect_handshake_message(ChangeCipherSpecMessage)
        self.decoder = self.negotiation_state.next_decoder
        self.next_expected_sequence_number = 0

        self.negotiation_state.server_verify_data = self.negotiation_state.cipher_suite.run_prf(
            secret=self.negotiation_state.master_secret,
            label=b'server finished',
            seed=self.negotiation_state.compute_handshake_messages_hash(),
            length=12,
        )

        server_finished = await self._expect_handshake_message_of_type(Finished)

        if not constant_time.bytes_eq(server_finished.verify_data, self.negotiation_state.server_verify_data):
            raise TLSConnectionError(f'Server-sent hash does not match expected hash.')

        self.status = TLSConnectionStatus.established

    def _check_client_certificate_usable(self, certificate_request: CertificateRequest) -> bool:
        if self.client_certificate is None:
            return False

        if certificate_request.certificate_authorities:
            client_certificate_issuer: cryptography.x509.Name = self.client_certificate.certificate.issuer
            issuer_bytes = client_certificate_issuer.public_bytes(backend=default_backend())
            asn1crypto_issuer = Name.load(issuer_bytes)
            if asn1crypto_issuer not in certificate_request.certificate_authorities:
                logger.warning(
                    f'Cannot use certificate because it is signed by "f{asn1crypto_issuer.human_friendly}" '
                    f'which is not in the list of accepted certificate authorities sent by the server.'
                )
                return False

        client_public_key = self.client_certificate.certificate.public_key()
        if not any(ct.is_compatible_with(client_public_key) for ct in certificate_request.certificate_types):
            logger.warning(
                f'Cannot use certificate because it has a {type(client_public_key).__name__} public key '
                f'which is not in the server certificate types.'
            )
            return False

        if not any(sa.is_compatible_with(client_public_key) for sa in certificate_request.supported_signature_algorithms):
            logger.warning(
                f'Cannot use certificate because it has a {type(client_public_key).__name__} public key '
                f'which is not supported by any of the server supported signature algorithms.'
            )
            return False

        return True

    async def _expect_handshake_message_of_type(self, t: Type[THandshakeMessageData]) -> THandshakeMessageData:
        next_message = await self._expect_handshake_message(HandshakeMessage)
        if next_message.message_type.value != t.message_type:
            self._return_message_to_head(next_message)
            raise UnexpectedHandshakeMessageTypeError(
                f'Received handshake message of type {next_message.message_type} but expected {t.message_type}',
                HandshakeMessageType.from_value(t.message_type),
                next_message.message_type,
            )
        return next_message.data

    async def _expect_handshake_message(self, t: Type[THandshakeMessageLax]) -> THandshakeMessageLax:
        next_message = await self._wait_for_next_handshake_message()
        if not isinstance(next_message, t):
            self._return_message_to_head(next_message)
            raise UnexpectedMessageContentTypeError(
                f'Received message of type {next_message.type} but expected {t.type}',
                t.type,
                next_message.type,
            )
        return next_message

    def _return_message_to_head(self, message: HandshakeMessageLax) -> None:
        self.incoming_handshake_messages.insert(0, message)

    async def _wait_for_next_handshake_message(self) -> HandshakeMessageLax:
        while len(self.incoming_handshake_messages) == 0:
            await self._pump_messages()
        return self.incoming_handshake_messages.pop(0)

    async def _pump_messages(self) -> None:
        next_messages = await self._wait_for_next_messages()
        for m in next_messages:
            if isinstance(m, AlertMessage):
                if m.description == AlertDescription.close_notify:
                    logger.info('Received close_notify alert.')
                    await self.close()
                elif m.level == AlertLevel.fatal:
                    logger.error('Received fatal alert %s', m.description)
                    raise TLSConnectionError('Handshake fatal alert', m)
                else:
                    logger.warning('Received warning alert %s', m.description)
            elif isinstance(m, ApplicationDataMessage):
                self.incoming_application_data.append(m.data)
            else:
                self.incoming_handshake_messages.append(m)
                if isinstance(m, HandshakeMessage):
                    self.negotiation_state.handshake_messages.append(m)

    async def send_application_data(self, data: bytes):
        if self.status != TLSConnectionStatus.established:
            raise RuntimeError('Cannot send application data while negotiation is ongoing.')

        await self._send_message(ApplicationDataMessage(data=data))

    async def receive_application_data(self) -> bytes:
        if self.status != TLSConnectionStatus.established:
            raise RuntimeError('Cannot receive application data while negotiation is ongoing, or connection is closed.')

        while len(self.incoming_application_data) == 0 and self.status != TLSConnectionStatus.closed:
            await self._pump_messages()
            await self._check_for_renegotiation()

        result = b''.join(self.incoming_application_data)
        self.incoming_application_data.clear()
        return result

    def closed(self):
        return self.status == TLSConnectionStatus.closed
