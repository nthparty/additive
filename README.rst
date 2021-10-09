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

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configuration details)::

    python -m pip install nose coverage
    nosetests --cover-erase

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`_::

    python additive/additive.py -v

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    python -m pip install pylint
    pylint additive

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/additive>`_ for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
