"""
Data structure for integers that supports additive secret sharing,
designed for use within secure multi-party computation (MPC) protocol
implementations.
"""
from __future__ import annotations
from typing import Optional, Union, Sequence
import doctest
import base64
import secrets

class share:
    """
    Data structure for additive secret shares of an integer.
    """
    def __init__(
            self: share, value: int,
            exponent: Optional[int] = 32, signed: Optional[bool] = False
        ):
        self.value = share._value_from_parameters(value, exponent, signed)
        self.exponent = exponent
        self.signed = signed

    @staticmethod
    def _value_from_parameters(value: int, exponent: int, signed: bool):
        """
        Confirm that supplied parameters are compatible and return an
        appropriate positive integer representation of the supplied value.
        """
        if not (1 <= exponent <= 128) or exponent % 8 != 0:
            raise ValueError(
                'exponent must be a positive multiple of 8 that is at most 128'
            )

        minimum = -(2 ** (exponent - 1)) if signed else 0
        maximum = 2 ** (exponent - 1 if signed else exponent)
        if not minimum <= value < maximum:
            raise ValueError(
                'value is not in range that can be represented using ' + \
                'supplied parameters'
            )

        return value + (maximum if signed else 0)

    @classmethod
    def _from_parameters(
            cls, value: int,
            exponent: Optional[int] = 32, signed: Optional[bool] = False
        ) -> share:
        """
        Internal method for constructing a share object without conducting
        any checks.
        """
        self = cls.__new__(cls)
        self.value = value
        self.exponent = exponent
        self.signed = signed
        return self

    @staticmethod
    def from_bytes(bs: Union[bytes, bytearray]) -> share:
        """
        Convert a share instance represented as a bytes-like object
        into a share object.
        """
        exponent =  (bs[0] + 1) >> 1
        if exponent <= 0 or exponent % 8 != 0:
            raise ValueError('invalid exponent in binary encoding of share')

        return share._from_parameters(
            value=int.from_bytes(bs[1:], 'little'),
            exponent=exponent,
            signed = bool(bs[0] % 2)
        )

    @staticmethod
    def from_base64(s: str) -> share:
        """
        Convert a share instance represented as a Base64 encoding of
        a bytes-like object into a share object.
        """
        return share.from_bytes(base64.standard_b64decode(s))

    def __add__(self: share, other: Union[share, int]) -> share:
        """
        Add two share instances (with base case support for
        the Python `sum` operator).
        """
        if isinstance(other, int) and other == 0:
            return self

        if self.exponent == other.exponent and self.signed == other.signed:
            s = share(
                (self.value + other.value) % (2 ** self.exponent),
                self.exponent
            )
            s.signed = self.signed
            return s

        raise ValueError(
            'shares must have compatible parameters to be added'
        )

    def __radd__(self: share, other: Union[share, int]) -> share:
        """
        Add two share instances (with base case support for
        the Python `sum` operator).
        """
        if isinstance(other, int) and other == 0:
            return self

        return other + self

    def to_int(self: share) -> int:
        """
        Obtain the integer value represented by a fully reconstructed
        aggregate share (no checking is performed that a share is fully
        reconstructed).
        """
        return self.value - (2 ** (self.exponent - 1)) if self.signed else self.value

    def to_bytes(self: share) -> bytes:
        """
        Return this share object encoded as a bytes-like object.
        """
        return \
            bytes([((self.exponent - 1) << 1) + int(self.signed)]) + \
            self.value.to_bytes(self.exponent // 8, 'little')

    def to_base64(self: share) -> str:
        """
        Return this share instance as a Base64 string.
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

    def __str__(self: share) -> str:
        """
        Return string representation of share object.
        """
        return 'share(' + ', '.join([
            str(self.value),
            str(self.exponent),
            str(self.signed)
        ]) + ')'

    def __repr__(self: share) -> str:
        """
        Return string representation of share object.
        """
        return str(self)

def shares(
        value: int, quantity: Optional[int] = 2,
        exponent: Optional[int] = 32, signed: Optional[bool] = False
    ) -> Sequence[share]:
    """
    Convert an integer into two or more secret shares constructed
    according to the supplied parameters.
    """
    value = share._value_from_parameters(
        value, exponent, signed
    )

    (ss, t) = ([], 0)
    for _ in range(quantity - 1):
        bs = secrets.token_bytes(exponent)
        v = int.from_bytes(bs, 'little') % (2 ** exponent)
        ss.append(share._from_parameters(
            v, exponent, signed
        ))
        t = (t + v) % (2 ** exponent)

    ss.append(share._from_parameters(
        (value + ((2 ** exponent) - t)) % (2 ** exponent),
        exponent, signed
    ))

    return ss

if __name__ == "__main__":
    doctest.testmod()
