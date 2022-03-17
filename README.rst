========
additive
========

Data structure for representing additive secret shares of integers, designed for use within secure multi-party computation (MPC) protocol implementations.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/additive.svg
   :target: https://badge.fury.io/py/additive
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/additive/badge/?version=latest
   :target: https://additive.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/additive/workflows/lint-test-cover-docs/badge.svg
   :target: https://github.com/nthparty/additive/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/additive/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/additive?branch=main
   :alt: Coveralls test coverage summary.

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

Examples
^^^^^^^^
This library makes it possible to concisely construct multiple secret shares from an integer::

    >>> from additive import shares
    >>> (a, b) = shares(123)
    >>> (c, d) = shares(456)
    >>> ((a + c) + (b + d)).to_int()
    579

It is possible to specify the exponent in the order of the finite field used to represent secret shares, as well as whether the encoding of the integer should support signed integers::

    >>> (s, t) = shares(-123, exponent=8, signed=True)
    >>> (s + t).to_int()
    -123

The number of shares can be specified explicitly (the default is two shares)::

    >>> (r, s, t) = shares(123, quantity=3)

The `share` data structure supports Python's built-in addition operators in order to enable both operations on shares and concise reconstruction of values from a collection of secret shares::

    >>> (r + s + t).to_int()
    123
    >>> sum([r, s, t]).to_int()
    123

In addition, conversion methods for Base64 strings and bytes-like objects are included to support encoding and decoding of ``share`` objects::

    >>> from additive import share
    >>> share.from_base64('HgEA').to_bytes().hex()
    '1e0100'
    >>> [s.to_base64() for s in shares(123)]
    ['PvmKMG8=', 'PoJ1z5A=']

Documentation
-------------
.. include:: toc.rst

The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py && make html

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org/>`_ (see ``setup.cfg`` for configuration details)::

    python -m pip install pytest pytest-cov
    python -m pytest

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`_::

    python additive/additive.py -v

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    python -m pip install pylint
    python -m pylint additive

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/additive>`_ for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.

Publishing
----------
This library can be published as a `package on PyPI <https://pypi.org/project/additive/>`_ by a package maintainer. Install the `wheel <https://pypi.org/project/wheel/>`_ package, remove any old build/distribution files, and package the source into a distribution archive::

    python -m pip install wheel
    rm -rf dist *.egg-info
    python setup.py sdist bdist_wheel

Next, install the `twine <https://pypi.org/project/twine/>`_ package and upload the package distribution archive to PyPI::

    python -m pip install twine
    python -m twine upload dist/*
