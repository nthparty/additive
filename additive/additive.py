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
    def _value_from_parameters(value: int, exponent: int, signed: bool) -> int:
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

        >>> share.from_bytes(bytes([30, 1] + ([0] * 31)))
        share(1, 16, False)

        An attempt to decode an invalid binary representation raises an exception.

        >>> share.from_bytes(bytes([12, 1] + ([0] * 31)))
        Traceback (most recent call last):
          ...
        ValueError: invalid exponent in binary encoding of share
        """
        exponent =  (bs[0] >> 1) + 1
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

        >>> share.from_base64('HgEA')
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
        >>> (ss, ts) = (shares(123, 3, signed=True), shares(-100, 3, signed=True))
        >>> ((ss[0] + ts[0]) + (ss[1] + ts[1]) + (ss[2] + ts[2])).to_int()
        23
        >>> ts = [shares(-n, 10, signed=True) for n in [123, 456, 789]]
        >>> sum(sum(ss) for ss in zip(*ts)).to_int()
        -1368

        When secret shares are added, it is not possible to determine
        whether the sum of the values they represent exceeds the maximum
        value that can be represented. If the sum does exceed the value,
        then the value reconstructed from the shares will wrap around.
        In the case of unsigned integer values, this corresponds to the
        usual behavior of field elements.

        >>> (a, b) = shares(255, exponent=8) # Unsigned one-byte integer.
        >>> (c, d) = shares(123, exponent=8) # Unsigned one-byte integer.
        >>> ((a + c) + (b + d)).to_int() == (255 + 123) % 256 == 122
        True

        In the case of signed integers, the sum will wrap from positive
        to negative (in a manner similar to that of typical implementations
        of signed integer addition in other popular languages and libraries).

        >>> (a, b) = shares(127, exponent=8, signed=True)
        >>> (c, d) = shares(2, exponent=8, signed=True)
        >>> ((a + c) + (b + d)).to_int() == -128 + ((127 + 2) % 128) == -127
        True

        An attempt to add secret shares that are represented using
        different finite fields (or are not all signed/unsigned)
        raises an exception.

        >>> share(0, 8) + share(0, 16)
        Traceback (most recent call last):
          ...
        ValueError: shares must have compatible parameters to be added
        >>> share(0, 8, signed=True) + share(0, 8, signed=False)
        Traceback (most recent call last):
          ...
        ValueError: shares must have compatible parameters to be added

        The examples below test this addition method for a range of share
        quantities and addition operation counts.

        >>> for quantity in range(2, 20):
        ...     for operations in range(2, 20):
        ...         vs = [
        ...             int.from_bytes(secrets.token_bytes(2), 'little')
        ...             for _ in range(operations)
        ...         ]
        ...         sss = [shares(v, quantity, signed=True) for v in vs]
        ...         assert(sum([sum(ss) for ss in zip(*sss)]).to_int() == sum(vs))
        """
        if isinstance(other, int) and other == 0:
            return self

        if self.exponent == other.exponent and self.signed == other.signed:
            return share._from_parameters(
                (
                    self.value + \
                    other.value + \
                    (2 ** (self.exponent - 1) if self.signed else 0)
                ) % (2 ** self.exponent),
                self.exponent,
                self.signed
            )

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

    def __mul__(self: share, scalar: int) -> share:
        """
        Multiply this secret share by an integer scalar. Note that all
        secret shares must be multiplied by the same integer scalar in
        order for the reconstructed value to reflect the correct effect.

        >>> (s, t) = shares(123)
        >>> s = s * 2
        >>> t = t * 2
        >>> (s + t).to_int()
        246
        >>> (s, t) = shares(123, exponent=16, signed=True)
        >>> s = s * 2
        >>> t = t * 2
        >>> (s + t).to_int()
        246
        >>> (s, t) = shares(123, exponent=16, signed=True)
        >>> s = s * -3
        >>> t = t * -3
        >>> (s + t).to_int()
        -369

        Multiplication of shares of signed integers by negative scalars is
        supported.

        >>> (s, t) = shares(123, exponent=16, signed=True)
        >>> s = s * -1
        >>> t = t * -1
        >>> (s + t).to_int()
        -123

        When secret shares are multiplied by a scalar, it is not possible to
        determine whether the result exceeds the range of values that can be
        represented. If the result does fall outside the range, then the value
        reconstructed from the shares will wrap around. In the case of unsigned
        integer values, this corresponds to the usual behavior of field elements.

        >>> (s, t) = shares(129, exponent=8)
        >>> s = s * 2
        >>> t = t * 2
        >>> (s + t).to_int()
        2

        In the case of signed integers, the result will wrap around the upper
        or lower boundary of the range that can be represented (in a manner
        similar to that of typical implementations of signed integer
        multiplication in other popular languages and libraries).

        >>> (a, b) = shares(65, exponent=8, signed=True)
        >>> ((2 * a) + (2 * b)).to_int() == -128 + (130 % 128) == -126
        True
        >>> (a, b) = shares(65, exponent=8, signed=True)
        >>> ((-2 * a) + (-2 * b)).to_int() == (-130) % 128 == 126
        True
        >>> (a, b) = shares(-65, exponent=8, signed=True)
        >>> ((-2 * a) + (-2 * b)).to_int() == -128 + (130 % 128) == -126
        True

        The scalar argument must be an integer.

        >>> (s, t) = shares(123)
        >>> s = s * 2.0
        Traceback (most recent call last):
          ...
        TypeError: scalar must be an integer

        Shares of unsigned integers cannot be multiplied by a negative scalar.

        >>> (s, t) = shares(123, signed=False)
        >>> s = s * -2
        Traceback (most recent call last):
          ...
        ValueError: shares of unsigned integers cannot be multiplied by a negative scalar

        The examples below test this scalar multiplication method for a range
        of share quantities and a number of random scalar values.

        >>> for quantity in range(2, 20):
        ...     for _ in range(100):
        ...         v = int.from_bytes(secrets.token_bytes(2), 'little')
        ...         c = -128 + int.from_bytes(secrets.token_bytes(1), 'little')
        ...         ss = shares(v, quantity, signed=True)
        ...         assert(sum([c * s for s in ss]).to_int() == c * v)
        """
        if not isinstance(scalar, int):
            raise TypeError('scalar must be an integer')

        if not self.signed and scalar < 0:
            raise ValueError(
                'shares of unsigned integers cannot be multiplied by a negative scalar'
            )

        # Restore the number of offset terms to be exactly one in the representation of
        # the signed integer in the share instance returned by this method.
        offset = (abs(scalar) - 1) * (2 ** (self.exponent - 1)) if self.signed else 0

        return share._from_parameters(
            value=((self.value * scalar) + offset) % (2 ** self.exponent),
            exponent=self.exponent,
            signed=self.signed
        )

    def __rmul__(self: share, scalar: int) -> share:
        """
        Multiply this secret share by an integer scalar. Note that all
        secret shares must be multiplied by the same integer scalar in
        order for the reconstructed value to reflect the correct effect.

        >>> (s, t) = shares(123)
        >>> s = 2 * s
        >>> t = 2 * t
        >>> (s + t).to_int()
        246
        >>> (r, s, t) = shares(123, 3, signed=True)
        >>> r = -2 * r
        >>> s = -2 * s
        >>> t = -2 * t
        >>> (r + s + t).to_int()
        -246
        """
        return self * scalar

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
        >>> (q, r, s, t) = shares(-123, 4, signed=True)
        >>> sum([q, r, s, t]).to_int()
        -123
        >>> all([
        ...     sum(shares(-123, q, signed=True)).to_int() == -123
        ...     for q in range(2, 7)
        ... ])
        True
        """
        return self.value - (2 ** (self.exponent - 1)) if self.signed else self.value

    def to_bytes(self: share) -> bytes:
        """
        Return a bytes-like object that encodes this :obj:`share` object.

        >>> share.from_base64('HgEA').to_bytes().hex()
        '1e0100'
        >>> ss = [s.to_bytes() for s in shares(123)]
        >>> sum(share.from_bytes(s) for s in ss).to_int()
        123
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

    Some compatibility and validity checks of the integer value and the parameter
    values are performed.

    >>> shares(123, 2, exponent=129)
    Traceback (most recent call last):
      ...
    ValueError: exponent must be a positive multiple of 8 that is at most 128
    >>> shares(256, 2, exponent=8)
    Traceback (most recent call last):
      ...
    ValueError: value is not in range that can be represented using supplied parameters
    >>> shares(128, 2, exponent=8, signed=True)
    Traceback (most recent call last):
      ...
    ValueError: value is not in range that can be represented using supplied parameters
    >>> shares(-129, 2, exponent=8, signed=True)
    Traceback (most recent call last):
      ...
    ValueError: value is not in range that can be represented using supplied parameters
    """
    value = share._value_from_parameters( # pylint: disable=W0212
        value, exponent, signed
    )

    # An offset term is added to the representation of every share of a signed
    # integer. This is necessary because the same operation (*i.e.*, addition)
    # is used to add secret shares and to reconstruct an integer value from
    # secret shares. Therefore, it is convenient to assume that all shares
    # (regardless which one it is or whether it is an initially created
    # instance or one created in the midst of a workflow) include an offset
    # term. For every addition operation between two share instances, exactly
    # one of the two offset terms is removed. Thus, only one offset term must
    # be removed when a value is reconstructed from shares.
    offset = (2 ** (exponent - 1)) if signed else 0

    (ss, t) = ([], 0)
    for _ in range(quantity - 1):
        bs = secrets.token_bytes(exponent)
        v = (int.from_bytes(bs, 'little') + offset) % (2 ** exponent)
        ss.append(share._from_parameters( # pylint: disable=W0212
            v, exponent, signed
        ))
        t = (t + v) % (2 ** exponent)

    ss.append(share._from_parameters( # pylint: disable=W0212
        (
            value + \
            ((2 ** exponent) - t) + \
            ( # Subtracting ``t`` in the above removed either an even or odd
              # number of ``offset`` terms. Thus, when ``quantity - 1`` is odd,
              # the total of the two terms above would result in a share that
              # has no offset term. Since this last share should also have an
              # ``offset`` term, ensure that the term is restored.
              offset if quantity % 2 == 0 else 0
            )
        ) % (2 ** exponent),
        exponent,
        signed
    ))

    return ss

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
