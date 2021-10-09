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

    >>> share(123)
    share(123, 32, False)
    >>> share(2**32 - 1, 32)
    share(4294967295, 32, False)
    >>> share(-(2**31), exponent=32, signed=True)
    share(0, 32, True)
    >>> share(2**32, 32)
    Traceback (most recent call last):
      ...
    ValueError: value is not in range that can be represented using supplied parameters
    >>> share(123, 12)
    Traceback (most recent call last):
      ...
    ValueError: exponent must be a positive multiple of 8 that is at most 128
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

        >>> share.from_bytes(bytes([32, 1] + ([0] * 31)))
        share(1, 16, False)
        >>> share.from_bytes(bytes([12, 1] + ([0] * 31)))
        Traceback (most recent call last):
          ...
        ValueError: invalid exponent in binary encoding of share
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

        >>> share.from_base64('IAEAAAA=')
        share(1, 16, False)
        """
        return share.from_bytes(base64.standard_b64decode(s))

    def __add__(self: share, other: Union[share, int]) -> share:
        """
        Add two share instances (with base case support for
        the Python `sum` operator).

        >>> (s, t) = shares(123)
        >>> s + t
        share(123, 32, False)
        >>> (s + t) + 0
        share(123, 32, False)
        >>> ((a, b), (c, d)) = (shares(123), shares(456))
        >>> ((a + c) + (b + d)).to_int()
        579
        >>> share(0, 8) + share(0, 16)
        Traceback (most recent call last):
          ...
        ValueError: shares must have compatible parameters to be added
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

        >>> (s, t) = shares(123)
        >>> s + t
        share(123, 32, False)
        >>> 0 + (s + t)
        share(123, 32, False)
        >>> sum(shares(123, 10))
        share(123, 32, False)
        """
        if isinstance(other, int) and other == 0:
            return self

        return other + self # pragma: no cover

    def to_int(self: share) -> int:
        """
        Obtain the integer value represented by a fully reconstructed
        aggregate share (no checking is performed that a share is fully
        reconstructed).

        >>> (s, t) = shares(123)
        >>> (s + t).to_int()
        123
        >>> (r, s, t) = shares(-123, 3, signed=True)
        >>> sum([r, s, t]).to_int()
        -123
        """
        return self.value - (2 ** (self.exponent - 1)) if self.signed else self.value

    def to_bytes(self: share) -> bytes:
        """
        Return this share object encoded as a bytes-like object.

        >>> share.from_base64('IAEAAAA=').to_bytes().hex()
        '1e0100'
        """
        return \
            bytes([((self.exponent - 1) << 1) + int(self.signed)]) + \
            self.value.to_bytes(self.exponent // 8, 'little')

    def to_base64(self: share) -> str:
        """
        Return this share instance as a Base64 string.

        >>> share(123, 128).to_base64()
        '/nsAAAAAAAAAAAAAAAAAAAA='
        >>> ss = [s.to_base64() for s in shares(-123, signed=True)]
        >>> sum(share.from_base64(s) for s in ss).to_int()
        -123
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

    def __str__(self: share) -> str:
        """
        Return string representation of share object.

        >>> str(share(123))
        'share(123, 32, False)'
        """
        return 'share(' + ', '.join([
            str(self.value),
            str(self.exponent),
            str(self.signed)
        ]) + ')'

    def __repr__(self: share) -> str:
        """
        Return string representation of share object.

        >>> share(123)
        share(123, 32, False)
        """
        return str(self)

def shares(
        value: int, quantity: Optional[int] = 2,
        exponent: Optional[int] = 32, signed: Optional[bool] = False
    ) -> Sequence[share]:
    """
    Convert an integer into two or more secret shares constructed
    according to the supplied parameters.

    >>> (s, t) = shares(123)
    >>> (s + t).to_int()
    123
    >>> ss = shares(123, 20)
    >>> len(ss)
    20
    >>> sum(ss).to_int()
    123
    >>> all(isinstance(s, share) for s in shares(123))
    True
    >>> shares(123, 2, 129)
    Traceback (most recent call last):
      ...
    ValueError: exponent must be a positive multiple of 8 that is at most 128
    """
    value = share._value_from_parameters( # pylint: disable=W0212
        value, exponent, signed
    )

    (ss, t) = ([], 0)
    for _ in range(quantity - 1):
        bs = secrets.token_bytes(exponent)
        v = int.from_bytes(bs, 'little') % (2 ** exponent)
        ss.append(share._from_parameters( # pylint: disable=W0212
            v, exponent, signed
        ))
        t = (t + v) % (2 ** exponent)

    ss.append(share._from_parameters( # pylint: disable=W0212
        (value + ((2 ** exponent) - t)) % (2 ** exponent),
        exponent, signed
    ))

    return ss

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
