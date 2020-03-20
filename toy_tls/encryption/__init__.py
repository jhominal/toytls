from __future__ import generator_stop

from abc import ABCMeta, abstractmethod

from toy_tls._tls_record import TLSRecordEncoder, TLSRecordDecoder


class EncryptionEngine(metaclass=ABCMeta):
    __slots__ = ()

    @property
    @abstractmethod
    def mac_key_length(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def enc_key_length(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def fixed_iv_length(self) -> int:
        raise NotImplementedError

    def _validate(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes):
        if len(mac_key) != self.mac_key_length:
            raise ValueError(f'mac_key must be of length {self.mac_key_length} but was {len(mac_key)}.')
        if len(enc_key) != self.enc_key_length:
            raise ValueError(f'enc_key must be of length {self.enc_key_length} but was {len(enc_key)}.')
        if len(fixed_iv) != self.fixed_iv_length:
            raise ValueError(f'fixed_iv must be of length {self.fixed_iv_length} but was {len(fixed_iv)}.')

    @abstractmethod
    def decoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordDecoder:
        raise NotImplementedError

    @abstractmethod
    def encoder(self, mac_key: bytes, enc_key: bytes, fixed_iv: bytes) -> TLSRecordEncoder:
        raise NotImplementedError
