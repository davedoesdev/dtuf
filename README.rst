\ |Build Status| |Coverage Status| |PyPI version|

Docker registry bindings for `The Update
Framework <http://theupdateframework.com/>`__ in Python. Uses
`dxf <https://github.com/davedoesdev/dxf>`__ to store TUF metadata and
target files in a Docker registry.

-  Easy-to-use Python module and command-line tool.
-  Distribute your data with the security and trust features of `The
   Update Framework <http://theupdateframework.com/>`__.
-  Backed by the scalability and flexbility of a `Docker
   registry <https://github.com/docker/distribution>`__.
-  No extra moving parts: just Python client-side and Docker registry
   server-side.

   -  Docker client and daemon not required.
   -  `Notary <https://github.com/docker/notary>`__ not required. See
      `this issue <https://github.com/docker/notary/issues/261>`__ for
      discussion.

-  Supports Docker registry schema v1 and v2.
-  Works on Python 2.7 and 3.4.

Examples
--------

Command-line example
~~~~~~~~~~~~~~~~~~~~

This assumes at least ``DTUF_HOST`` has been set to the hostname of a
Docker registry (see `Usage <#usage>`__ below). You may need to set
``DTUF_USERNAME`` and ``DTUF_PASSWORD`` too depending on the registry
you're using.

You can run your own registry or use a hosted one such as Docker Hub
(``registry-1.docker.io``).

If you want to run your own, see this `example
script <test/cli_example.sh>`__ or the `unit
tests <test/conftest.py>`__. There are also full instructions available
`here <https://github.com/docker/distribution/blob/master/docs/deploying.md>`__.

.. code:: shell

    # On the master machine
    $ echo 'Hello World!' > demo.txt
    $ dtuf create-root-key fred/demo
    $ dtuf create-metadata-keys fred/demo
    $ dtuf create-metadata fred/demo
    $ dtuf push-target fred/demo demo.txt demo.txt
    $ dtuf push-metadata fred/demo
    # pub key is in dtuf_repos/fred/demo/master/keys/root_key.pub
    # distribute it out-of-band

    # On some other machine
    $ dtuf pull-metadata fred/demo root_key.pub
    demo.txt
    $ dtuf pull-target fred/demo demo.txt
    Hello World!

    # Update on the master machine
    $ echo 'Update World!' > demo.txt
    $ echo 'Another World!' > demo2.txt
    $ dtuf push-target fred/demo demo.txt demo.txt
    $ dtuf push-target fred/demo demo2.txt demo2.txt
    $ dtuf push-metadata fred/demo

    # On the other machine
    $ dtuf pull-metadata fred/demo
    demo.txt
    demo2.txt
    $ dtuf pull-target fred/demo demo.txt
    Update World!
    $ dtuf pull-target fred/demo demo2.txt
    Another World!

Module example
~~~~~~~~~~~~~~

This example uses the Docker Hub. Change the username, password and
repository name to suit.

Publish on the master machine:

.. code:: python

    from dtuf import DTufMaster

    def auth(dtuf, response):
        dtuf.authenticate('fred', 'somepassword', response=response)

    dtuf = DTufMaster('registry-1.docker.io', 'fred/demo', auth=auth)

    with open('demo.txt', 'w') as f:
        f.write('Hello World!\n')

    dtuf.create_root_key()
    dtuf.create_metadata_keys()
    dtuf.create_metadata()
    dtuf.push_target('demo.txt', 'demo.txt')
    dtuf.push_metadata()
    # pub key is in dtuf_repos/fred/demo/master/keys/root_key.pub
    # distribute it out-of-band

Retrieve on some other machine:

.. code:: python

    from dtuf import DTufCopy

    def auth(dtuf, response):
        dtuf.authenticate('barney', 'otherpassword', response=response)

    dtuf = DTufCopy('registry-1.docker.io', 'fred/demo', auth=auth)

    with open('root_key.pub', 'r') as f:
        assert dtuf.pull_metadata(f.read()) == ['demo.txt']

    s = ''
    for download in dtuf.pull_target('demo.txt'):
        for chunk in download:
            s += chunk
    assert s == 'Hello World!\n'

Usage
-----

The module API is described
`here <http://rawgit.davedoesdev.com/davedoesdev/dtuf/master/docs/_build/html/index.html>`__.

Environment variables
~~~~~~~~~~~~~~~~~~~~~

The ``dtuf`` command-line tool uses the following environment variables.
Only ``DTUF_HOST`` is strictly required but you may need to set others
depending on your set up.

-  ``DTUF_HOST`` - Host where Docker registry is running
-  ``DTUF_INSECURE`` - Set this to ``1`` if you want to connect to the
   registry using ``http`` rather than ``https`` (which is the default).
-  ``DTUF_USERNAME`` - Name of user to authenticate as.
-  ``DTUF_PASSWORD`` - User's password.
-  ``DTUF_REPOSITORIES_ROOT`` - Directory under which TUF metadata
   should be stored. Note that the repository name is appended to this
   before storing the metadata. Defaults to ``dtuf_repos`` in the
   current working directory.
-  ``DTUF_AUTH_HOST`` - If set, always perform token authentication to
   this host, overriding the value returned by the registry.
-  ``DTUF_PROGRESS`` - If this is set to ``1``, a progress bar is
   displayed (on standard error) during ``dtuf push-target``,
   ``dtuf push-metadata``, ``dtuf pull-metadata`` and
   ``dtuf pull-target``. If this is set to ``0``, a progress bar is not
   displayed. If this is set to any other value, a progress bar is only
   displayed if standard error is a terminal.
-  ``DTUF_BLOB_INFO`` - Set this to ``1`` if you want
   ``dtuf pull-target`` to prepend each blob with its digest and size
   (printed in plain text, separated by a space and followed by a
   newline).
-  ``DTUF_ROOT_KEY_PASSWORD`` - Password to use for encrypting the TUF
   root private key. Used by ``dtuf create-root-key``,
   ``dtuf create-metadata`` and ``dtuf reset-keys``. If unset then
   you'll be prompted for the password.
-  ``DTUF_TARGETS_KEY_PASSWORD`` - Password to use for encrypting the
   TUF targets private key. Used by ``dtuf create-metadata-keys``,
   ``dtuf create-metadata``, ``dtuf reset-keys`` and
   ``dtuf push-metadata``. If unset then you'll be prompted for the
   password.
-  ``DTUF_SNAPSHOT_KEY_PASSWORD`` - Password to use for encrypting the
   TUF snapshot private key. Used by ``dtuf create-metadata-keys``,
   ``dtuf create-metadata``, ``dtuf reset-keys`` and
   ``dtuf push-metadata``. If unset then you'll be prompted for the
   password.
-  ``DTUF_TIMESTAMP_KEY_PASSWORD`` - Password to use for enrypting the
   TUF timestamp private key. Used by ``dtuf create-metadata-keys``,
   ``dtuf create-metadata``, ``dtuf reset-keys`` and
   ``dtuf push-metadata``. If unset then you'll be prompted for the
   password.
-  ``DTUF_ROOT_LIFETIME`` - Lifetime of the TUF `root
   metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L235>`__.
   After this time expires, you'll need to use ``dtuf reset-keys`` and
   ``dtuf push-metadata`` to re-sign the metadata. Defaults to 1 year.
-  ``DTUF_TARGETS_LIFETIME`` - Lifetime of the TUF `targets
   metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L246>`__.
   After this time expires, you'll need to use ``dtuf push-metadata`` to
   re-sign the metadata. Defaults to 3 months.
-  ``DTUF_SNAPSHOT_LIFETIME`` - Lifetime of the TUF `snapshot
   metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L268>`__.
   After this time expires, you'll need to use ``dtuf push-metadata`` to
   re-sign the metadata. Defaults to 1 week.
-  ``DTUF_TIMESTAMP_LIFETIME`` - Lifetime of the TUF `timestamp
   metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L276>`__.
   After this time expires, you'll need to use ``dtuf push-metadata`` to
   re-sign the metadata. Defaults to 1 day.
-  ``DTUF_LOG_FILE`` - Name of file to write log messages into. Defaults
   to ``dtuf.log`` in the current working directory. Set it to an empty
   string to disable logging to a file.
-  ``DTUF_FILE_LOG_LEVEL`` - Name of the Python `logging
   level <https://docs.python.org/2/library/logging.html#logging-levels>`__
   to use when deciding which messages to write to the log file.
   Defaults to ``WARNING``.
-  ``DTUF_CONSOLE_LOG_LEVEL`` - Name of the Python logging level to use
   when deciding which messages to write to the console. Defaults to
   ``WARNING``.

Command line options
~~~~~~~~~~~~~~~~~~~~

You can use the following options with ``dtuf``. In each case, supply
the name of the repository on the registry you wish to work with as the
second argument.

Creating, updating and uploading data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  ``dtuf create-root-key <repo>``

       Create TUF root keypair for the repository.

       The private key is written to
       ``$DTUF_REPOSITORIES_ROOT/<repo>/master/keys/root_key`` and can
       be moved offline once you've used ``dtuf create-metadata``.
       You'll need it again if you use ``dtuf reset-keys`` when the root
       metadata expires.

       The public key is written to
       ``$DTUF_REPOSITORIES_ROOT/<repo>/master/keys/root_key.pub`` and
       can be given to others for use when retrieving a copy of the
       repository metadata with ``dtuf pull-metadata``.

-  ``dtuf create-metadata-keys <repo>``

       Create TUF metadata keypairs for the repository.

       The keys are written to the
       ``$DTUF_REPOSITORIES_ROOT/<repo>/master/keys`` directory. The
       public keys have a ``.pub`` extension.

       You can move the private keys offline once you've used
       ``dtuf push-metadata`` to publish the repository.

       You don't need to give out the metadata public keys since they're
       published on the repository.

-  ``dtuf create-metadata <repo>``

       Create and sign the TUF metadata for the repository.

       You only need to do this once for each repository, and the
       repository's root and metadata private keys must be available.

-  ``dtuf reset-keys <repo>``

       Re-sign the TUF metadata for the repository.

       Call this if you've generated new root or metadata keys (because
       one of the keys has been compromised, for example) but you don't
       want to delete the repository and start again.

-  ``dtuf push-target <repo> <target> <file|@target>...``

       Upload data to the repository and update the local TUF metadata

       The metadata isn't uploaded until you use ``dtuf push-metadata``.

       The data is given a name (known as the ``target``) and can come
       from a list of files or existing target names. Existing target
       names should be prepended with ``@`` in order to distinguish them
       from filenames.

-  ``dtuf del-target <repo> <target>...``

       Delete targets (data) from the repository and update the local
       TUF metadata.

       The metadata isn't updated on the registry until you use
       ``dtuf push-metadata``.

       Note that the registry doesn't support deletes yet so expect an
       error.

-  ``dtuf push-metadata <repo>``

       Upload local TUF metadata to the repository.

       The TUF metadata consists of a list of targets (which were
       uploaded by ``dtuf push-target``), a snapshot of the state of the
       metadata (list of hashes), a timestamp and a list of public keys.

       The metadata except for the list of public keys will be signed
       here. The list of public keys was signed (along with the rest of
       the metadata) when you used ``dtuf create-metadata`` (or
       ``dtuf reset-keys``).

-  ``dtuf list-master-targets <repo>``

       Print the names of all the targets defined in the local TUF
       metadata.

-  ``dtuf get-master-expirations <repo>``

       Print the expiration dates of the TUF metadata.

Downloading data
^^^^^^^^^^^^^^^^

-  ``dtuf pull-metadata <repo> [<root-pubkey-file>|-]``

       Download TUF metadata from the repository.

       The metadata is checked for expiry and verified against the root
       public key for the repository.

       You only need to supply the root public key once, and you should
       obtain it from the person who uploaded the metadata. If you
       specify ``-`` then the key is read from standard input instead of
       a file.

       Target data is not downloaded - use ``dtuf pull-target`` for
       that.

       A list of targets which have been updated since you last
       downloaded them will be printed to standard output, one per line.

-  ``dtuf pull-target <repo> <target>...``

       Download targets (data) from the repository to standard output.

       Each target's data consists of one of more separate blobs
       (depending on how many > were uploaded). All of them will be
       downloaded.

-  ``dtuf blob-sizes <repo> <target>...``

       Print the sizes of all the blobs which make up a list of targets.

-  ``dtuf check-target <repo> <target> <file>...``

       Check whether the hashes of a target's blobs match the hashes of
       list of files. An error message will be displayed if not and the
       exit code won't be 0.

-  ``dtuf list-copy-targets <repo>``

       Print the names of all the targets defined in the local copy of
       the TUF metadata.

-  ``dtuf get-copy-expirations <repo>``

       Print the expiration dates of the local copy of the TUF metadata.

-  ``dtuf list-repos``

       Print the names of all the repositories in the registry.

Authentication tokens
---------------------

``dtuf`` automatically obtains Docker registry authentication tokens
using your ``DTUF_USERNAME`` and ``DTUF_PASSWORD`` environment variables
as necessary.

However, if you wish to override this then you can use the following
command:

-  ``dtuf auth <repo> <action>...``

       Authenticate to the registry using ``DTUF_USERNAME`` and
       ``DTUF_PASSWORD``, and print the resulting token.

       ``action`` can be ``pull``, ``push`` or ``*``.

If you assign the token to the ``DTUF_TOKEN`` environment variable, for
example:

``DTUF_TOKEN=$(dtuf auth fred/demo pull)``

then subsequent ``dtuf`` commands will use the token without needing
``DTUF_USERNAME`` and ``DTUF_PASSWORD`` to be set.

Note however that the token expires after a few minutes, after which
``dtuf`` will exit with ``EACCES``.

Installation
------------

.. code:: shell

    pip install python-dtuf

Licence
-------

`MIT <https://raw.github.com/davedoesdev/dtuf/master/LICENCE>`__

Tests
-----

.. code:: shell

    make test

Lint
----

.. code:: shell

    make lint

Code Coverage
-------------

.. code:: shell

    make coverage

`coverage.py <http://nedbatchelder.com/code/coverage/>`__ results are
available
`here <http://rawgit.davedoesdev.com/davedoesdev/dtuf/master/htmlcov/index.html>`__.

Coveralls page is `here <https://coveralls.io/r/davedoesdev/dtuf>`__.

.. |Build Status| image:: https://travis-ci.org/davedoesdev/dtuf.png
   :target: https://travis-ci.org/davedoesdev/dtuf
.. |Coverage Status| image:: https://coveralls.io/repos/davedoesdev/dtuf/badge.png?branch=master
   :target: https://coveralls.io/r/davedoesdev/dtuf?branch=master
.. |PyPI version| image:: https://badge.fury.io/py/python-dtuf.png
   :target: http://badge.fury.io/py/python-dtuf
