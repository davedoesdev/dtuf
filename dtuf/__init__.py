"""
Docker registry bindings for The Update Framework
"""

# pylint: disable=superfluous-parens, wrong-import-order

try:
    import urllib.parse as urlparse
except ImportError:
    # pylint: disable=import-error
    import urlparse

import json
import threading
import hashlib
import re
from os import path, getcwd, remove, makedirs, listdir
from datetime import datetime, timedelta
from decorator import decorator
import fasteners
from dxf import DXFBase, DXF, hash_file, hash_bytes, split_digest
import dxf.exceptions
from dtuf import exceptions
import iso8601

class _DTufConnection(object):
    def __init__(self, url):
        import tuf.conf
        self._url = url
        _, target = urlparse.urlparse(url).path.split('//')
        pos = _skip_consistent_target_digest(target)
        if pos == 0:
            self._dgst = _updater_dxf.get_alias(target)[0]
        else:
            self._dgst = 'sha256:' + target[0:pos-1]
        self._it, self._size = _updater_dxf.pull_blob(
            self._dgst, size=True, chunk_size=tuf.conf.CHUNK_SIZE)
        self._it = self._it.__iter__()
        self._end = object()
        self._count = 0
        if _updater_progress:
            _updater_progress(self._dgst, b'', self._size)

    def info(self):
        return {'Content-Length': str(self._size)}

    def read(self, _):
        chunk = next(self._it, self._end)
        if chunk is self._end:
            return b''
        if _updater_progress:
            _updater_progress(self._dgst, chunk, self._size)
        self._count += len(chunk)
        return chunk

    def close(self):
        # give dxf a chance to check the digest
        if self._count == self._size:
            next(self._it, self._end)

    def __str__(self):
        return "dtuf connection to %s" % self._url

def _open_connection(url):
    return _DTufConnection(url)

def _is_metadata_file(target):
    return target.endswith('root.json') or \
           target.endswith('targets.json') or \
           target.endswith('snapshot.json') or \
           target.endswith('timestamp.json')

_tuf_lock = threading.Lock()
_updater_dxf = None
_updater_progress = None

def _tuf_clear():
    import tuf.keydb
    import tuf.roledb
    import tuf.conf
    # pylint: disable=global-statement
    global _updater_dxf, _updater_progress
    _updater_dxf = None
    _updater_progress = None
    tuf.keydb.clear_keydb()
    tuf.roledb.clear_roledb()
    tuf.conf.repository_directory = None

def _locked(lock, setup, f, self, *args, **kwargs):
    with _tuf_lock:
        with lock:
            _tuf_clear()
            try:
                if setup:
                    setup()
                return f(self, *args, **kwargs)
            finally:
                _tuf_clear()

@decorator
def _master_repo_locked(f, self, *args, **kwargs):
    # pylint: disable=protected-access
    return _locked(self._master_repo_lock, None, f, self, *args, **kwargs)

@decorator
def _copy_repo_locked(f, self, *args, **kwargs):
    # pylint: disable=global-statement,protected-access
    def setup():
        import tuf.conf
        import tuf.download
        # pylint: disable=protected-access
        tuf.download._open_connection = _open_connection
        global _updater_dxf
        _updater_dxf = self._dxf
        tuf.conf.repository_directory = self._copy_repo_dir
    return _locked(self._copy_repo_lock, setup, f, self, *args, **kwargs)

_consistent_prefix_re = re.compile(r'[a-f0-9]{' +
                                   str(hashlib.sha256().digest_size * 2) +
                                   r'}\.')

def _skip_consistent_target_digest(basename):
    match = _consistent_prefix_re.match(basename)
    return match.end() if match else 0

def _strip_consistent_target_digest(filename):
    dirname, basename = path.split(filename)
    return path.join(dirname,
                     basename[_skip_consistent_target_digest(basename):])

def _remove_keys(metadata):
    import tuf.keydb
    import tuf.roledb
    for keyid in tuf.roledb.get_roleinfo(metadata.rolename)['keyids']:
        metadata.remove_verification_key(tuf.keydb.get_key(keyid))

def _write_with_progress(it, dgst, size, out, progress):
    if progress:
        progress(dgst, b'', size)
    for chunk in it:
        if progress:
            progress(dgst, chunk, size)
        out.write(chunk)

class DTufBase(object):
    """
    Class for communicating with a Docker v2 registry.
    Contains only operations which aren't related to pushing and pulling data
    to repositories in the registry using
    `The Update Framework <https://github.com/theupdateframework/tuf>`_.

    Can act as a context manager. For each context entered, a new
    `requests.Session <http://docs.python-requests.org/en/latest/user/advanced/#session-objects>`_
    is obtained. Connections to the same host are shared by the session.
    When the context exits, all the session's connections are closed.

    If you don't use :class:`DTufBase` as a context manager, each request
    uses an ephemeral session. If you don't read all the data from an iterator
    returned by :meth:`DTufCopy.pull_target` then the underlying connection
    won't be closed until Python garbage collects the iterator.
    """
    def __init__(self, host, auth=None, insecure=False, auth_host=None):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DTufBase` object and a HTTP response object. It should call :meth:`authenticate` on ``dtuf_obj`` with a username, password and ``response`` before it returns.
        :type auth: function(dtuf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str
        """
        self._dxf = DXFBase(host, self._wrap_auth(auth), insecure, auth_host)

    def _wrap_auth(self, auth=None):
        return lambda dxf_obj, response: auth(self, response) if auth else None

    @property
    def token(self):
        """
        str: Authentication token. This will be obtained automatically when
        you call :meth:`authenticate`. If you've obtained a token
        previously, you can also set it but be aware tokens expire quickly.
        """
        return self._dxf.token

    @token.setter
    def token(self, value):
        self._dxf.token = value

    def authenticate(self,
                     username=None, password=None,
                     actions=None, response=None):
        """
        Authenticate to the registry, using a username and password if supplied,
        otherwise as the anonymous user.

        :param username: User name to authenticate as.
        :type username: str

        :param password: User's password.
        :type password: str

        :param actions: If you know which types of operation you need to make on the registry, specify them here. Valid actions are ``pull``, ``push`` and ``*``.
        :type actions: list

        :param response: When the ``auth`` function you passed to :class:`DTufBase`'s constructor is called, it is passed a HTTP response object. Pass it back to :meth:`authenticate` to have it automatically detect which actions are required.
        :type response: requests.Response

        :rtype: str
        :returns: Authentication token, if the registry supports bearer tokens. Otherwise ``None``, and HTTP Basic auth is used.
        """
        return self._dxf.authenticate(username, password, actions, response)

    def list_repos(self):
        """
        List all repositories in the registry.

        :rtype: list
        :returns: List of repository names.
        """
        return self._dxf.list_repos()

    def __enter__(self):
        self._dxf.__enter__()
        return self

    def __exit__(self, *args):
        return self._dxf.__exit__(*args)

class _DTufCommon(DTufBase):
    # pylint: disable=too-many-arguments,super-init-not-called
    def __init__(self, host, repo, repos_root=None,
                 auth=None, insecure=False, auth_host=None):
        self._dxf = DXF(host, repo, self._wrap_auth(auth), insecure, auth_host)
        self._repo_root = path.join(repos_root if repos_root else path.join(getcwd(), 'dtuf_repos'), repo)

# pylint: disable=too-many-instance-attributes
class DTufMaster(_DTufCommon):
    """
    Class for creating, updating and publishing data to repositories in a
    Docker registry using
    `The Update Framework <https://github.com/theupdateframework/tuf>`_ (TUF).
    """
    # pylint: disable=too-many-arguments
    def __init__(self, host, repo, repos_root=None,
                 auth=None, insecure=False, auth_host=None,
                 root_lifetime=None, targets_lifetime=None,
                 snapshot_lifetime=None, timestamp_lifetime=None):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that. The repository is used to store data and TUF metadata describing the data.
        :type repo: str

        :param repos_root: Directory under which to store TUF metadata. Note that the value of ``repo`` and the literal string ``master`` are appended to this directory name before storing the metadata. Defaults to ``dtuf_repos`` in the current working directory.
        :type repos_root: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DTufBase` object and a HTTP response object. It should call :meth:`DTufBase.authenticate` on ``dtuf_obj`` with a username, password and ``response`` before it returns.
        :type auth: function(dtuf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str

        :param root_lifetime: Lifetime of the TUF `root metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L235>`_. After this time expires, you'll need to call :meth:`reset_keys` and :meth:`push_metadata` to re-sign the metadata. Defaults to ``tuf.repository_tool.ROOT_EXPIRATION`` (1 year).
        :type root_lifetime: datetime.timedelta

        :param targets_lifetime: Lifetime of the TUF `targets metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L246>`_. After this time expires, you'll need to call :meth:`push_metadata` to re-sign the metadata. Defaults to ``tuf.repository_tool.TARGETS_EXPIRATION`` (3 months).
        :type targets_lifetime: datetime.timedelta

        :param snapshot_lifetime: Lifetime of the TUF `snapshot metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L268>`_. After this time expires, you'll need to call :meth:`push_metadata` to re-sign the metadata. Defaults to ``tuf.repository_tool.SNAPSHOT_EXPIRATION`` (1 week).
        :type snapshot_lifetime: datetime.timedelta

        :param timestamp_lifetime: Lifetime of the TUF `timestamp metadata <https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt#L276>`_. After this time expires, you'll need to call :meth:`push_metadata` to re-sign the metadata. Defaults to ``tuf.repository_tool.TIMESTAMP_EXPIRATION`` (1 day).
        :type timestamp_lifetime: datetime.timedelta
        """
        super(DTufMaster, self).__init__(host, repo, repos_root,
                                         auth, insecure, auth_host)
        self._master_dir = path.join(self._repo_root, 'master')
        self._master_repo_lock = fasteners.process_lock.InterProcessLock(
            path.join(self._master_dir, 'lock'))
        self._keys_dir = path.join(self._master_dir, 'keys')
        self._root_key_file = path.join(self._keys_dir, 'root_key')
        self._targets_key_file = path.join(self._keys_dir, 'targets_key')
        self._snapshot_key_file = path.join(self._keys_dir, 'snapshot_key')
        self._timestamp_key_file = path.join(self._keys_dir, 'timestamp_key')
        self._master_repo_dir = path.join(self._master_dir, 'repository')
        self._master_targets_dir = path.join(self._master_repo_dir, 'targets')
        self._master_staged_dir = path.join(self._master_repo_dir, 'metadata.staged')
        from tuf.repository_tool import ROOT_EXPIRATION,                 \
                                        TARGETS_EXPIRATION,              \
                                        SNAPSHOT_EXPIRATION,             \
                                        TIMESTAMP_EXPIRATION
        self._root_lifetime = timedelta(seconds=ROOT_EXPIRATION) \
            if root_lifetime is None else root_lifetime
        self._targets_lifetime = timedelta(seconds=TARGETS_EXPIRATION) \
            if targets_lifetime is None else targets_lifetime
        self._snapshot_lifetime = timedelta(seconds=SNAPSHOT_EXPIRATION) \
            if snapshot_lifetime is None else snapshot_lifetime
        self._timestamp_lifetime = timedelta(seconds=TIMESTAMP_EXPIRATION) \
            if timestamp_lifetime is None else timestamp_lifetime

    @_master_repo_locked
    def create_root_key(self, password=None):
        """
        Create root keypair for the repository.

        The private key is written to ``<repos_root>/<repo>/master/keys/root_key`` and can be moved offline once you've called :meth:`create_metadata`. You'll need it again if you call :meth:`reset_keys` when the root metadata expires.

        The public key is written to ``<repos_root>/<repo>/master/keys/root_key.pub`` and can be given to others for use when retrieving a copy of the repository metadata with :meth:`DTufCopy.pull_metadata`.

        :param password: Password to use for encrypting the private key. You'll be prompted for one if you don't supply it.
        :type password: str
        """
        from tuf.repository_tool import generate_and_write_rsa_keypair
        if password is None:
            print('generating root key...')
        generate_and_write_rsa_keypair(self._root_key_file, password=password)

    @_master_repo_locked
    def create_metadata_keys(self,
                             targets_key_password=None,
                             snapshot_key_password=None,
                             timestamp_key_password=None):
        """
        Create TUF metadata keypairs for the repository.

        The keys are written to the ``<repos_root>/<repo>/master/keys`` directory. The public keys have a ``.pub`` extension.

        You can move the private keys offline once you've called :meth:`create_metadata` but you'll need them again when you call :meth:`push_metadata` to publish the repository.

        You don't need to give out the metadata public keys since they're published on the repository.

        :param targets_key_password: Password to use for encrypting the TUF targets private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param snapshot_key_password: Password to use for encrypting the TUF snapshot private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param timestamp_key_password: Password to use for encrypting the TUF timestamp private key. You'll be prompted for one if you don't supply it.
        :type password: str
        """
        from tuf.repository_tool import generate_and_write_rsa_keypair
        if targets_key_password is None:
            print('generating targets key...')
        generate_and_write_rsa_keypair(self._targets_key_file,
                                       password=targets_key_password)
        if snapshot_key_password is None:
            print('generating snapshot key...')
        generate_and_write_rsa_keypair(self._snapshot_key_file,
                                       password=snapshot_key_password)
        if timestamp_key_password is None:
            print('generating timestamp key...')
        generate_and_write_rsa_keypair(self._timestamp_key_file,
                                       password=timestamp_key_password)

    # pylint: disable=too-many-locals
    def _add_metadata(self,
                      repository,
                      root_key_password=None,
                      targets_key_password=None,
                      snapshot_key_password=None,
                      timestamp_key_password=None):
        from tuf.repository_tool import import_rsa_publickey_from_file, \
                                        import_rsa_privatekey_from_file
        # Add root key to repository
        public_root_key = import_rsa_publickey_from_file(
            self._root_key_file + '.pub')
        if root_key_password is None:
            print('importing root key...')
        private_root_key = import_rsa_privatekey_from_file(
            self._root_key_file,
            root_key_password)
        repository.root.add_verification_key(public_root_key)
        repository.root.load_signing_key(private_root_key)
        repository.root.expiration = datetime.now() + self._root_lifetime

        # Add targets key to repository
        public_targets_key = import_rsa_publickey_from_file(
            self._targets_key_file + '.pub')
        if targets_key_password is None:
            print('importing targets key...')
        private_targets_key = import_rsa_privatekey_from_file(
            self._targets_key_file,
            targets_key_password)
        repository.targets.add_verification_key(public_targets_key)
        repository.targets.load_signing_key(private_targets_key)

        # Add snapshot key to repository
        public_snapshot_key = import_rsa_publickey_from_file(
            self._snapshot_key_file + '.pub')
        if snapshot_key_password is None:
            print('importing snapshot key...')
        private_snapshot_key = import_rsa_privatekey_from_file(
            self._snapshot_key_file,
            snapshot_key_password)
        repository.snapshot.add_verification_key(public_snapshot_key)
        repository.snapshot.load_signing_key(private_snapshot_key)

        # Add timestamp key to repository
        public_timestamp_key = import_rsa_publickey_from_file(
            self._timestamp_key_file + '.pub')
        if timestamp_key_password is None:
            print('importing timestamp key...')
        private_timestamp_key = import_rsa_privatekey_from_file(
            self._timestamp_key_file,
            timestamp_key_password)
        repository.timestamp.add_verification_key(public_timestamp_key)
        repository.timestamp.load_signing_key(private_timestamp_key)

        # Write out metadata
        repository.write(consistent_snapshot=True)

    @_master_repo_locked
    def create_metadata(self,
                        root_key_password=None,
                        targets_key_password=None,
                        snapshot_key_password=None,
                        timestamp_key_password=None):
        """
        Create and sign the TUF metadata for the repository.

        You only need to call this once for each repository, and the
        repository's root and metadata private keys must be available.

        :param root_key_password: Password to use for decrypting the TUF root private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param targets_key_password: Password to use for decrypting the TUF targets private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param snapshot_key_password: Password to use for decrypting the TUF snapshot private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param timestamp_key_password: Password to use for decrypting the TUF timestamp private key. You'll be prompted for one if you don't supply it.
        :type password: str
        """
        from tuf.repository_tool import create_new_repository
        # Create repository object and add metadata to it
        self._add_metadata(create_new_repository(self._master_repo_dir),
                           root_key_password,
                           targets_key_password,
                           snapshot_key_password,
                           timestamp_key_password)

    @_master_repo_locked
    def reset_keys(self,
                   root_key_password=None,
                   targets_key_password=None,
                   snapshot_key_password=None,
                   timestamp_key_password=None):
        """
        Re-sign the TUF metadata for the repository.

        Call this if you've generated new root or metadata keys (because one
        of the keys has been compromised, for example) but you don't want to
        delete the repository and start again.

        :param root_key_password: Password to use for decrypting the TUF root private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param targets_key_password: Password to use for decrypting the TUF targets private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param snapshot_key_password: Password to use for decrypting the TUF snapshot private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param timestamp_key_password: Password to use for decrypting the TUF timestamp private key. You'll be prompted for one if you don't supply it.
        :type password: str
        """
        from tuf.repository_tool import load_repository
        # Load repository object
        repository = load_repository(self._master_repo_dir)
        #  pylint: disable=no-member
        # Remove keys
        _remove_keys(repository.root)
        _remove_keys(repository.targets)
        _remove_keys(repository.snapshot)
        _remove_keys(repository.timestamp)
        # Add metadata to repository (adds keys)
        self._add_metadata(repository,
                           root_key_password,
                           targets_key_password,
                           snapshot_key_password,
                           timestamp_key_password)

    @_master_repo_locked
    def push_target(self, target, *filename_or_target_list, **kwargs):
        """
        Upload data to the repository and update the local TUF metadata.

        The metadata isn't uploaded until you call :meth:`push_metadata`.

        The data is given a name (known as the ``target``) and can come from a
        list of files or existing target names.

        :param target: Name to give the data.
        :type target: str

        :param filename_or_target_list: List of data to upload. Each item is either a filename or an existing target name. Existing target names should be prepended with ``@`` in order to distinguish them from filenames.
        :type filename_or_target_list: list

        :param kwargs: Contains an optional ``progress`` member which is a function to call as the upload progresses. The function will be called with the hash of the content of the file currently being uploaded, the blob just read from the file and the total size of the file.
        :type kwargs: dict({'progress': function(dgst, chunk, total)})
        """
        progress = kwargs.get('progress')
        if _is_metadata_file(target) or \
           _skip_consistent_target_digest(target) != 0:
            raise exceptions.DTufReservedTargetError(target)
        dgsts = []
        for filename_or_target in filename_or_target_list:
            if filename_or_target.startswith('@'):
                with open(path.join(self._master_targets_dir,
                                    filename_or_target[1:]), 'rb') as f:
                    manifest = f.read().decode('utf-8')
                dgsts += self._dxf.get_alias(manifest=manifest)
            else:
                dgsts.append(self._dxf.push_blob(filename_or_target, progress))
        manifest = self._dxf.make_manifest(*dgsts)
        manifest_filename = path.join(self._master_targets_dir, target)
        with open(manifest_filename, 'wb') as f:
            f.write(manifest.encode('utf-8'))
        self._dxf.push_blob(manifest_filename, progress)

    @_master_repo_locked
    def del_target(self, target):
        """
        Delete a target (data) from the repository and update the local TUF
        metadata.

        The metadata isn't updated on the registry until you call
        :meth:`push_metadata`.

        Note that the registry doesn't support deletes yet so expect an error.

        :param target: The name you gave to the data when it was uploaded using :meth:`push_target`.
        :type target: str
        """
        from tuf.repository_tool import Repository
        # read target manifest
        manifest_filename = path.join(self._master_targets_dir, target)
        with open(manifest_filename, 'rb') as f:
            manifest = f.read()
        manifest_dgst = hash_bytes(manifest)
        # remove target manifest
        remove(manifest_filename)
        # remove consistent snapshot links for target
        for f in Repository.get_filepaths_in_directory(self._master_targets_dir):
            _, basename = path.split(f)
            if basename[_skip_consistent_target_digest(basename):] == target:
                remove(f)
        # delete blobs manifest points to
        for dgst in self._dxf.get_alias(manifest=manifest.decode('utf-8')):
            self._dxf.del_blob(dgst)
        # delete manifest blob
        self._dxf.del_blob(manifest_dgst)

    # pylint: disable=too-many-locals
    @_master_repo_locked
    def push_metadata(self,
                      targets_key_password=None,
                      snapshot_key_password=None,
                      timestamp_key_password=None,
                      progress=None):
        """
        Upload local TUF metadata to the repository.

        The TUF metadata consists of a list of targets (which were uploaded by
        :meth:`push_target`), a snapshot of the state of the metadata (list of
        hashes), a timestamp and a list of public keys.

        This function signs the metadata except for the list of public keys,
        so you'll need to supply the password to the respective private keys.

        The list of public keys was signed (along with the rest of the metadata)
        with the root private key when you called :meth:`create_metadata`
        (or :meth:`reset_keys`).

        :param targets_key_password: Password to use for decrypting the TUF targets private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param snapshot_key_password: Password to use for decrypting the TUF snapshot private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param timestamp_key_password: Password to use for decrypting the TUF timestamp private key. You'll be prompted for one if you don't supply it.
        :type password: str

        :param progress: Optional function to call as the upload progresses. The function will be called with the hash of the content of the file currently being uploaded, the blob just read from the file and the total size of the file.
        :type progress: function(dgst, chunk, total)
        """
        from tuf.repository_tool import load_repository, \
                                        Repository, \
                                        import_rsa_privatekey_from_file
        # Load repository object
        repository = load_repository(self._master_repo_dir)
        #  pylint: disable=no-member

        # Update targets
        repository.targets.clear_targets()
        repository.targets.add_targets([
            _strip_consistent_target_digest(f)
            for f in Repository.get_filepaths_in_directory(self._master_targets_dir)])

        # Update expirations
        repository.targets.expiration = datetime.now() + self._targets_lifetime
        repository.snapshot.expiration = datetime.now() + self._snapshot_lifetime
        repository.timestamp.expiration = datetime.now() + self._timestamp_lifetime

        # Load targets key
        if targets_key_password is None:
            print('importing targets key...')
        private_targets_key = import_rsa_privatekey_from_file(
            self._targets_key_file,
            targets_key_password)
        repository.targets.load_signing_key(private_targets_key)

        # Load snapshot key
        if snapshot_key_password is None:
            print('importing snapshot key...')
        private_snapshot_key = import_rsa_privatekey_from_file(
            self._snapshot_key_file,
            snapshot_key_password)
        repository.snapshot.load_signing_key(private_snapshot_key)

        # Load timestamp key
        if timestamp_key_password is None:
            print('importing timestamp key...')
        private_timestamp_key = import_rsa_privatekey_from_file(
            self._timestamp_key_file,
            timestamp_key_password)
        repository.timestamp.load_signing_key(private_timestamp_key)

        # Update metadata
        repository.write(consistent_snapshot=True)

        # Upload root.json and timestamp.json without hash prefix
        for f in ['root.json', 'timestamp.json']:
            dgst = self._dxf.push_blob(path.join(self._master_staged_dir, f),
                                       progress)
            self._dxf.set_alias(f, dgst)

        # Upload consistent snapshot versions of current metadata files...
        # first load timestamp.json
        with open(path.join(self._master_staged_dir, 'timestamp.json'), 'rb') as f:
            timestamp_data = f.read()
        # hash of content is timestamp prefix
        _, dgst = split_digest(hash_bytes(timestamp_data))
        timestamp_cs = dgst + '.timestamp.json'
        files = [timestamp_cs]
        # parse timestamp data
        timestamp = json.loads(timestamp_data.decode('utf-8'))
        # get snapshot prefix
        snapshot_cs = timestamp['signed']['meta']['snapshot.json']['hashes']['sha256'] + '.snapshot.json'
        files.append(snapshot_cs)
        # load prefixed snapshot.json
        with open(path.join(self._master_staged_dir, snapshot_cs), 'rb') as f:
            snapshot_data = f.read()
        # parse snapshot data
        snapshot = json.loads(snapshot_data.decode('utf-8'))
        # get targets and root prefixes
        targets_cs = snapshot['signed']['meta']['targets.json']['hashes']['sha256'] + '.targets.json'
        files.append(targets_cs)
        root_cs = snapshot['signed']['meta']['root.json']['hashes']['sha256'] + '.root.json'
        files.append(root_cs)
        # Upload metadata
        for f in files:
            self._dxf.push_blob(path.join(self._master_staged_dir, f), progress)

    @_master_repo_locked
    def list_targets(self):
        """
        Return the names of all the targets defined in the local TUF metadata.

        :returns: List of target names
        :rtype: list
        """
        from tuf.repository_tool import load_repository
        repository = load_repository(self._master_repo_dir)
        #  pylint: disable=no-member
        return [p.lstrip(path.sep) for p in repository.targets.target_files]

    @_master_repo_locked
    def get_expirations(self):
        """
        Return the expiration dates of the TUF metadata.

        :returns: A dictionary containing `datetime <https://docs.python.org/2/library/datetime.html#datetime.datetime>`_ values for the keys ``root``, ``targets``, ``snapshot`` and ``timestamp``.
        :rtype: dict
        """
        from tuf.repository_tool import load_repository
        repository = load_repository(self._master_repo_dir)
        # pylint: disable=no-member
        return {
            'root': repository.root.expiration,
            'targets': repository.targets.expiration,
            'snapshot': repository.snapshot.expiration,
            'timestamp': repository.timestamp.expiration
        }

class DTufCopy(_DTufCommon):
    """
    Class for downloading data from repositories in a Docker registry using
    `The Update Framework <https://github.com/theupdateframework/tuf>`_ (TUF).
    """
    # pylint: disable=too-many-arguments
    def __init__(self, host, repo, repos_root=None,
                 auth=None, insecure=False, auth_host=None):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that. The repository is used to retrieve data and TUF metadata describing the data.
        :type repo: str

        :param repos_root: Directory under which to store TUF metadata. Note that the value of ``repo`` and the literal string ``copy`` are appended to this directory name before storing the metadata. Defaults to ``dtuf_repos`` in the current working directory.
        :type repos_root: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DTufBase` object and a HTTP response object. It should call :meth:`DTufBase.authenticate` with a username, password and ``response`` before it returns.
        :type auth: function(dtuf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str
        """
        super(DTufCopy, self).__init__(host, repo, repos_root,
                                       auth, insecure, auth_host)
        self._copy_dir = path.join(self._repo_root, 'copy')
        self._copy_repo_lock = fasteners.process_lock.InterProcessLock(
            path.join(self._copy_dir, 'lock'))
        self._copy_repo_dir = path.join(self._copy_dir, 'repository')
        self._copy_targets_dir = path.join(self._copy_repo_dir, 'targets')
        self._repository_mirrors = {
            'dtuf': {
                'url_prefix': 'https://' + host + '/' + repo,
                'metadata_path': '',
                'targets_path': '',
                'confined_target_dirs': ['']
            }
        }

    # pylint: disable=too-many-locals
    @_copy_repo_locked
    def pull_metadata(self, root_public_key=None, progress=None):
        """
        Download TUF metadata from the repository.

        The metadata is checked for expiry and verified against the root public
        key for the repository.

        You only need to supply the root public key once, and you should obtain
        it from the person who uploaded the metadata.

        Target data is not downloaded - use :meth:`pull_target` for that.

        :param root_public_key: PEM-encoded root public key. Obtain this from the repository's owner, who generates the key using :meth:`DTufMaster.create_root_key` on the repository master.
        :type root_public_key: str

        :param progress: Optional function to call as the download progresses. The function will be called with the hash of the metadata currently being download, the blob just read from the repository and the total size of the metadata.
        :type progress: function(dgst, chunk, total)

        :returns: List of targets which have been updated since you last downloaded them (using :meth:`pull_target`).
        :rtype: list
        """
        import tuf.keydb
        import tuf.roledb
        import tuf.client.updater
        import tuf.util
        import tuf.formats
        import tuf.sig
        from tuf import BadSignatureError
        # pylint: disable=global-statement
        global _updater_progress
        _updater_progress = progress
        for d in ['current', 'previous']:
            try:
                makedirs(path.join(self._copy_repo_dir, 'metadata', d))
            except OSError as exception:
                import errno
                if exception.errno != errno.EEXIST:
                    raise
        # If root public key was passed, we shouldn't rely on the current
        # version but instead retrieve a new one and verify it using
        # the public key.
        if root_public_key:
            dgst = self._dxf.get_alias('root.json')[0]
            temp_file = tuf.util.TempFile()
            try:
                it, size = self._dxf.pull_blob(dgst, size=True)
                _write_with_progress(it, dgst, size, temp_file, progress)
                metadata = temp_file.read()
                metadata_signable = json.loads(metadata.decode('utf-8'))
                tuf.formats.check_signable_object_format(metadata_signable)
                # pylint: disable=protected-access
                f = tuf.client.updater.Updater._ensure_not_expired
                f = getattr(f, '__func__', f)
                f(None, metadata_signable['signed'], 'root')
                # This metadata is claiming to be root.json
                # Get the keyid of the signature and use it to add the root
                # public key to the keydb. Thus when we verify the signature
                # the root public key will be used for verification.
                keyid = metadata_signable['signatures'][0]['keyid']
                tuf.keydb.add_key({
                    'keytype': 'rsa',
                    'keyid': keyid,
                    'keyval': {'public': root_public_key}
                }, keyid)
                tuf.roledb.add_role('root', {
                    'keyids': [keyid],
                    'threshold': 1
                })
                if not tuf.sig.verify(metadata_signable, 'root'):
                    raise BadSignatureError('root')
                temp_file.move(path.join(self._copy_repo_dir,
                                         'metadata',
                                         'current',
                                         'root.json'))
            except:
                temp_file.close_temp_file()
                raise
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        updater.refresh(False)
        targets = updater.all_targets()
        updated_targets = updater.updated_targets(
            targets, self._copy_targets_dir)
        if path.isdir(self._copy_targets_dir):
            targets = dict([(t['filepath'][1:], True) for t in targets])
            for t in listdir(self._copy_targets_dir):
                if t not in targets:
                    remove(path.join(self._copy_targets_dir, t))
        return [t['filepath'][1:] for t in updated_targets]

    @_copy_repo_locked
    def _get_digests(self, target, sizes=False):
        import tuf.client.updater
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        tgt = updater.target(target)
        updater.download_target(tgt, self._copy_targets_dir)
        with open(path.join(self._copy_targets_dir, target), 'rb') as f:
            manifest = f.read().decode('utf-8')
        return self._dxf.get_alias(manifest=manifest, sizes=sizes)

    def pull_target(self, target, digests_and_sizes=False):
        """
        Download a target (data) from the repository.

        Target data consists of one or more separate blobs (depending on how
        many were uploaded). Because this function returns an iterator, download
        of each blob occurs lazily.

        Target information is stored in the TUF metadata, so you should have
        called :meth:`pull_metadata` previously.

        :param target: Name of the target to download.
        :type target: str

        :param digests_and_sizes: Whether to return the hash and size of each downloaded blob as well.
        :type digests_and_sizes: bool

        :returns: If ``digests_and_sizes`` is falsey, an iterator which yields for each blob an iterator over its content. If ``digests_and_sizes`` is truthy, an iterator which yields for each blob a tuple containing an iterator over its content, the hash of its content and its size.
        :rtype: iterator
        """
        for dgst in self._get_digests(target):
            if digests_and_sizes:
                it, size = self._dxf.pull_blob(dgst, size=True)
                yield it, dgst, size
            else:
                yield self._dxf.pull_blob(dgst)

    def blob_sizes(self, target):
        """
        Return the sizes of all the blobs which make up a target.

        :param target: Name of target
        :type target: str

        :returns: List of blob sizes
        :rtype: list
        """
        return [size for _, size in self._get_digests(target, sizes=True)]

    def check_target(self, target, *filenames):
        """
        Check whether the hashes of a target's blobs match the hashes of a
        given list of filenames.

        Raises `dxf.exceptions.DXFDigestMismatchError` if they don't.

        :param target: Name of target to check.
        :type target: str

        :param filenames: Names of files to check against.
        :type filenames: list
        """
        blob_dgsts = self._get_digests(target)
        if len(blob_dgsts) != len(filenames):
            raise dxf.exceptions.DXFDigestMismatchError(filenames, blob_dgsts)
        for i, filename in enumerate(filenames):
            file_dgst = hash_file(filename)
            if file_dgst != blob_dgsts[i]:
                raise dxf.exceptions.DXFDigestMismatchError(file_dgst, blob_dgsts[i])

    @_copy_repo_locked
    def list_targets(self):
        """
        Return the names of all the targets defined in the local copy of the
        TUF metadata.

        :returns: List of target names
        :rtype: list
        """
        import tuf.client.updater
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        return [t['filepath'][1:] for t in updater.all_targets()]

    @_copy_repo_locked
    def get_expirations(self):
        """
        Return the expiration dates of the local TUF metadata copy.

        :returns: A dictionary containing `datetime <https://docs.python.org/2/library/datetime.html#datetime.datetime>`_ values for the keys ``root``, ``targets``, ``snapshot`` and ``timestamp``.
        :rtype: dict
        """
        import tuf.client.updater
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        metadata = updater.metadata['current']
        return {
            'root': iso8601.parse_date(metadata['root']['expires']),
            'targets': iso8601.parse_date(metadata['targets']['expires']),
            'snapshot': iso8601.parse_date(metadata['snapshot']['expires']),
            'timestamp': iso8601.parse_date(metadata['timestamp']['expires'])
        }
