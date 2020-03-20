from __future__ import generator_stop

from attr import attrs, attrib


@attrs(slots=True, frozen=True, auto_attribs=True)
class _IntRangeValidator:
    min: int = attrib()
    max: int = attrib()

    def __call__(self, instance, attribute, value):
        if not isinstance(value, int):
            raise ValueError("Value must be an int.")
        if value < self.min or value > self.max:
            raise ValueError(f"Value must be between {self.min} and {self.max} inclusive.")


uint8 = _IntRangeValidator(min=0, max=0xff)
uint16 = _IntRangeValidator(min=0, max=0xffff)
uint32 = _IntRangeValidator(min=0, max=0xffffffff)


@attrs(slots=True, frozen=True, auto_attribs=True)
class _BytesBoundedLengthValidator:
    min_length: int = attrib()
    max_length: int = attrib()

    def __call__(self, instance, attribute, value):
        if not isinstance(value, bytes):
            raise ValueError("Value must be a byte string.")
        if len(value) > self.max_length or len(value) < self.min_length:
            raise ValueError(f"Value length must be between {self.min_length} and {self.max_length} inclusive.")


def fixed_bytes(length: int):
    return _BytesBoundedLengthValidator(min_length=length, max_length=length)


def bounded_bytes(*, min_length: int = 0, max_length: int):
    return _BytesBoundedLengthValidator(min_length=min_length, max_length=max_length)
