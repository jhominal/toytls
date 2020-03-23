from __future__ import generator_stop

import logging
import os
from asyncio import StreamReader, StreamWriter
from functools import partial
from typing import Type, TypeVar, Generic, Iterable, Sequence, Optional, List

from attr import attrs, attrib
from attr.validators import instance_of
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.hashes import HashAlgorithm, Hash
from cryptography.hazmat.primitives.hmac import HMAC

from toy_tls._cipher_suites import IncompatiblePublicKeyError
from toy_tls._common import ProtocolVersion
from toy_tls._data_reader import FullDataReader
from toy_tls._data_writer import DataWriter, SupportsEncode
from toy_tls._tls_record import TLSPlaintextRecord, TLSRecordEncoder, InitialTLSRecordEncoder, TLSRecordDecoder, \
    TLSRecordHeader, InitialTLSRecordDecoder
from toy_tls.content import ContentMessage, ContentType, ApplicationDataMessage
from toy_tls.content.alert import AlertMessage, AlertLevel, AlertDescription
from toy_tls.content.change_cipher_spec import ChangeCipherSpecMessage
from toy_tls.content.extensions.ec_points_formats import EllipticCurvePointFormatList
from toy_tls.content.extensions.elliptic_curves import NamedCurveList
from toy_tls.content.extensions.server_name import ServerNameList
from toy_tls.content.extensions.signature_algorithms import SupportedSignatureAlgorithms, SignatureScheme
from toy_tls.content.handshake import HandshakeMessage, ClientHello, Extension, CipherSuite, HandshakeMessageType, \
    HandshakeMessageData, ServerHello, PeerCertificate, ServerKeyExchange, ServerHelloDone, ClientKeyExchange, Finished
from toy_tls.validation import fixed_bytes

logger = logging.getLogger(__name__)


class TLSConnectionError(Exception):
    pass


def run_prf(hash_algorithm: HashAlgorithm, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError(f'Length must be > 0 but was {length}')
    initial_hmac = HMAC(key=secret, algorithm=hash_algorithm, backend=default_backend())

    buf = bytearray()
    iterated_a = label + seed
    while len(buf) < length:
        hmac_a = initial_hmac.copy()
        hmac_a.update(iterated_a)
        iterated_a = hmac_a.finalize()

        hmac_p = initial_hmac.copy()
        hmac_p.update(iterated_a)
        hmac_p.update(label)
        hmac_p.update(seed)
        buf.extend(hmac_p.finalize())

    return bytes(buf[:length])


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

    def initialize_codec(self):
        engine = self.cipher_suite.encryption_engine
        key_material = run_prf(
            hash_algorithm=self.cipher_suite.hash_for_prf,
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

    def compute_handshake_messages_hash(self) -> bytes:
        hash_context = Hash(algorithm=self.cipher_suite.hash_for_prf, backend=default_backend())
        for message in self.handshake_messages:
            hash_context.update(get_encoded_bytes(message))
        return hash_context.finalize()


TContentMessage = TypeVar('TContentMessage', bound=ContentMessage)
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


@attrs(auto_attribs=True, slots=True)
class TLSConnection:
    reader: StreamReader = attrib(kw_only=True)
    writer: StreamWriter = attrib(kw_only=True)

    protocol_version: ProtocolVersion = attrib(init=False, default=ProtocolVersion.TLS_1_2)

    encoder: TLSRecordEncoder = attrib(init=False, default=InitialTLSRecordEncoder())
    decoder: TLSRecordDecoder = attrib(init=False, default=InitialTLSRecordDecoder())

    negotiation_state: TLSNegotiationState = attrib(init=False, default=TLSNegotiationState())
    next_sequence_number_to_send: int = attrib(init=False, default=0)
    next_expected_sequence_number: int = attrib(init=False, default=0)

    buffer: IncomingBuffer = attrib(init=False, factory=IncomingBuffer)
    incoming_messages: List[ContentMessage] = attrib(init=False, factory=list)

    async def _send_fatal_alert(self, description: AlertDescription):
        return await self._send_message(
            AlertMessage(
                level=AlertLevel.fatal,
                description=description,
            )
        )

    async def _send_message(self, message: ContentMessage, protocol_version: Optional[ProtocolVersion] = None):
        if isinstance(message, HandshakeMessage):
            self.negotiation_state.handshake_messages.append(message)
        message_bytes = get_encoded_bytes(message)
        record = TLSPlaintextRecord(
            content_type=message.type,
            protocol_version=protocol_version or self.protocol_version,
            data=message_bytes,
        )
        await self._send_tls_record(record)

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

    async def do_initial_handshake(self, hostname: str):
        self.negotiation_state.client_random = os.urandom(32)
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
            extensions=[
                Extension.from_data(
                    ServerNameList.create(hostname.encode('ascii'))
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
                            SignatureScheme.ecdsa_secp521r1_sha512,
                            SignatureScheme.rsa_pkcs1_sha512,
                            SignatureScheme.ecdsa_secp384r1_sha384,
                            SignatureScheme.rsa_pkcs1_sha384,
                            SignatureScheme.ecdsa_secp256r1_sha256,
                            SignatureScheme.rsa_pkcs1_sha256,
                            SignatureScheme.ecdsa_sha1,
                            SignatureScheme.rsa_pkcs1_sha1,
                        ]
                    )
                ),
            ]
        )
        client_hello_message = HandshakeMessage(
            message_type=HandshakeMessageType.client_hello,
            data=client_hello,
        )
        await self._send_message(client_hello_message, protocol_version=ProtocolVersion.TLS_1_0)

        server_hello = await self._expect_handshake_message_of_type(ServerHello)
        if server_hello.server_version < ProtocolVersion.TLS_1_2:
            await self._send_fatal_alert(description=AlertDescription.protocol_version)
            raise TLSConnectionError(
                f'Server Hello set TLS version {server_hello.server_version} '
                f'but {ProtocolVersion.TLS_1_2} was required.'
            )
        self.negotiation_state.server_random = server_hello.random
        self.negotiation_state.cipher_suite = server_hello.cipher_suite
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

        await self._expect_handshake_message_of_type(ServerHelloDone)

        # OPTION ClientCert: Send Client Certificate Chain

        key_exchange = server_parameters.execute_key_exchange()

        self.negotiation_state.master_secret = run_prf(
            hash_algorithm=self.negotiation_state.cipher_suite.hash_for_prf,
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

        self.negotiation_state.initialize_codec()

        await self._send_message(ChangeCipherSpecMessage())
        self.encoder = self.negotiation_state.next_encoder
        self.next_sequence_number_to_send = 0

        client_verify_data = run_prf(
            hash_algorithm=self.negotiation_state.cipher_suite.hash_for_prf,
            secret=self.negotiation_state.master_secret,
            label=b'client finished',
            seed=self.negotiation_state.compute_handshake_messages_hash(),
            length=12,
        )
        await self._send_message(
            HandshakeMessage(
                message_type=HandshakeMessageType.finished,
                data=Finished(verify_data=client_verify_data),
            ),
        )

        await self._expect_message_with_content_type(ChangeCipherSpecMessage)
        self.decoder = self.negotiation_state.next_decoder
        self.next_expected_sequence_number = 0

        server_verify_data = run_prf(
            hash_algorithm=self.negotiation_state.cipher_suite.hash_for_prf,
            secret=self.negotiation_state.master_secret,
            label=b'server finished',
            seed=self.negotiation_state.compute_handshake_messages_hash(),
            length=12,
        )

        server_finished = await self._expect_handshake_message_of_type(Finished)

        if not constant_time.bytes_eq(server_finished.verify_data, server_verify_data):
            raise TLSConnectionError(f'Server-sent hash does not match expected hash.')

    async def _expect_handshake_message_of_type(self, t: Type[THandshakeMessageData]) -> THandshakeMessageData:
        next_message = await self._expect_message_with_content_type(HandshakeMessage)
        if next_message.message_type.value != t.message_type:
            await self._send_fatal_alert(description=AlertDescription.protocol_version)
            raise TLSConnectionError(
                f'Received handshake message of type {next_message.message_type} but expected {t.message_type}'
            )
        return next_message.data

    async def _expect_message_with_content_type(self, t: Type[TContentMessage]) -> TContentMessage:
        next_message = await self._wait_for_next_message()
        if not isinstance(next_message, t):
            raise TLSConnectionError(f'Received message of type {next_message.type} but expected {t.type}')
        return next_message

    async def _wait_for_next_message(self) -> ContentMessage:
        while len(self.incoming_messages) == 0:
            next_messages = await self._wait_for_next_messages()
            for m in next_messages:
                if isinstance(m, AlertMessage):
                    if m.level == AlertLevel.fatal:
                        logger.error('Received fatal alert %s', m.description)
                        raise TLSConnectionError('Handshake fatal alert', m)
                    else:
                        logger.warning('Received warning alert %s', m.description)
                else:
                    self.incoming_messages.append(m)
                    if isinstance(m, HandshakeMessage):
                        self.negotiation_state.handshake_messages.append(m)

        return self.incoming_messages.pop(0)

    async def send_application_data(self, data: bytes):
        await self._send_message(ApplicationDataMessage(data=data))

    async def receive_application_data(self) -> bytes:
        received_data = await self._expect_message_with_content_type(ApplicationDataMessage)
        return received_data.data
