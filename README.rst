========
additive
========

Data structure for representing additive secret shares of integers, designed for use within secure multi-party computation (MPC) protocol implementations.

|pypi|

.. |pypi| image:: https://badge.fury.io/py/additive.svg
   :target: https://badge.fury.io/py/additive
   :alt: PyPI version and link.

Purpose
-------
This library provides a data structure and methods that make it possible work with *n*-out-of-*n* `additive secret shares <https://en.wikipedia.org/wiki/Secret_sharing>`_ of integers within secure multi-party computation (MPC) protocol implementations. Secret shares of signed and unsigned integers can be represented using elements from finite fields, with support currently limited to fields having a power-of-two order.

Package Installation and Usage
------------------------------
The package is available on `PyPI <https://pypi.org/project/additive/>`_::

    python -m pip install additive

The library can be imported in the usual ways::

    import additive
    from additive import *

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/additive>`_ for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
