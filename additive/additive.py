"""
Data structure for representing additive secret shares of integers,
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
    Data structure for representing an additive secret share of an integer.

    :param value: Integer value to be split into secret shares.
    :param exponent: Exponent in finite field order of ``2 ** exponent``
        that is at least ``8``, at most ``128``, and is a multiple of ``8``.
    :param signed: Flag indicating whether ``value`` is a signed integer;
        this flag affects the specific way in which a secret share is
        represented internally and shifts the range of integer values that
        can be represented from ``range(0, 2 ** exponent)`` to
        ``[-(2 ** (exponent - 1)), (2 ** (exponent - 1)) - 1)``.

    Normally, the :obj:`shares` function should be used to construct a list
    of :obj:`share` objects that have correct internal structure.

    >>> ((a, b), (c, d)) = (shares(123), shares(456))
    >>> ((a + c) + (b + d)).to_int()
    579

    Direct construction of :obj:`share` objects is made available to enable
    other use cases, protocols, and/or extensions.

    >>> share(123)
    share(123, 32, False)
    >>> share(2**32 - 1, 32)
    share(4294967295, 32, False)
    >>> share(-(2**31), exponent=32, signed=True)
    share(0, 32, True)

    Some compatibility and validity checks of the supplied parameter values
    are performed.

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
        Internal method for constructing a :obj:`share` object without conducting
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
        Convert a secret share represented as a bytes-like object
        into a :obj:`share` object.

        >>> share.from_bytes(bytes([32, 1] + ([0] * 31)))
        share(1, 16, False)

        An attempt to decode an invalid binary representation raises an exception.

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
        Convert a secret share represented as a Base64 encoding of
        a bytes-like object into a :obj:`share` object.

        >>> share.from_base64('IAEAAAA=')
        share(1, 16, False)
        """
        return share.from_bytes(base64.standard_b64decode(s))

    def __add__(self: share, other: Union[share, int]) -> share:
        """
        Add two secret shares (represented as :obj:`share` objects);
        ``0`` is supported as an input to accommodate the base case
        required by the Python ``sum`` operator.

        >>> (s, t) = shares(123)
        >>> s + t
        share(123, 32, False)
        >>> (s + t) + 0
        share(123, 32, False)
        >>> ((a, b), (c, d)) = (shares(123), shares(456))
        >>> ((a + c) + (b + d)).to_int()
        579

        An attempt to add secret shares that are represented using
        different finite fields (or are not all signed/unsigned)
        raises an exception.

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
        Add two secret shares (represented as :obj:`share` objects);
        ``0`` is supported as an input to accommodate the base case
        required by the Python ``sum`` operator.

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
        aggregate of secret shares (no checking is performed that the
        :obj:`share` object represents a complete reconstruction).

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
        Return a bytes-like object that encodes this :obj:`share` object.

        >>> share.from_base64('IAEAAAA=').to_bytes().hex()
        '1e0100'
        """
        return \
            bytes([((self.exponent - 1) << 1) + int(self.signed)]) + \
            self.value.to_bytes(self.exponent // 8, 'little')

    def to_base64(self: share) -> str:
        """
        Return a Base64 string representation of this :obj:`share` object.

        >>> share(123, 128).to_base64()
        '/nsAAAAAAAAAAAAAAAAAAAA='
        >>> ss = [s.to_base64() for s in shares(-123, signed=True)]
        >>> sum(share.from_base64(s) for s in ss).to_int()
        -123
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

    def __str__(self: share) -> str:
        """
        Return string representation of this :obj:`share` object.

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
        Return string representation of this :obj:`share` object.

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

    :param value: Integer value to be split into secret shares.
    :param quantity: Number of secret shares (at least two) to construct
        and return.
    :param exponent: Exponent in finite field order of ``2 ** exponent``
        that is at least ``8``, at most ``128``, and is a multiple of ``8``.
    :param signed: Flag indicating whether ``value`` is a signed integer;
        this flag affects the specific way in which a secret share is
        represented internally and shifts the range of integer values that
        can be represented from ``{0, ..., (2 ** exponent) - 1}`` to
        ``{-(2 ** (exponent - 1)), ..., (2 ** (exponent - 1)) - 1}``.

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

    Some compatibility and validity checks of the supplied parameter values
    are performed.

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
