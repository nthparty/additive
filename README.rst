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
This library provides a data structure and methods that make it possible work with *n*-out-of-*n* `additive secret shares <https://en.wikipedia.org/wiki/Secret_sharing>`__ of integers within secure multi-party computation (MPC) protocol implementations. Secret shares of signed and unsigned integers can be represented using elements from finite fields, with support currently limited to fields having a power-of-two order.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/additive>`__::

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

.. |share| replace:: ``share``
.. _share: https://additive.readthedocs.io/en/latest/_source/additive.html#additive.additive.share

The |share|_ data structure supports Python's built-in addition operators, enabling both operations on shares and concise reconstruction of values from a collection of shares::

    >>> (r + s + t).to_int()
    123
    >>> sum([r, s, t]).to_int()
    123

In addition, conversion methods for Base64 strings and bytes-like objects are included to support encoding and decoding of |share|_ objects::

    >>> from additive import share
    >>> share.from_base64('HgEA').to_bytes().hex()
    '1e0100'
    >>> [s.to_base64() for s in shares(123)]
    ['PvmKMG8=', 'PoJ1z5A=']

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__::

    python -m pip install .[docs,lint]

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__::

    python -m pip install .[docs]
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details)::

    python -m pip install .[test]
    python -m pytest

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__::

    python additive/additive.py -v

Style conventions are enforced using `Pylint <https://www.pylint.org>`__::

    python -m pip install .[lint]
    python -m pylint additive

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/additive>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/additive>`__ by a package maintainer. First, install the dependencies required for packaging and publishing::

    python -m pip install .[publish]

Remove any old build/distribution files and package the source into a distribution archive::

    rm -rf build dist *.egg-info
    python -m build --sdist --wheel .

Finally, upload the package distribution archive to `PyPI <https://pypi.org>`__ using the `twine <https://pypi.org/project/twine>`__ package::

    python -m twine upload dist/*
