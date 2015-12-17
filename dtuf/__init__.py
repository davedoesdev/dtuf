# pylint: disable=superfluous-parens, wrong-import-order

try:
    import urllib.parse as urlparse
except ImportError:
    # pylint: disable=import-error
    import urlparse

import json
import threading
from os import path, getcwd, remove, makedirs, listdir
from datetime import datetime, timedelta
from tuf.repository_tool import ROOT_EXPIRATION,                 \
                                TARGETS_EXPIRATION,              \
                                SNAPSHOT_EXPIRATION,             \
                                TIMESTAMP_EXPIRATION,            \
                                generate_and_write_rsa_keypair,  \
                                import_rsa_publickey_from_file,  \
                                import_rsa_privatekey_from_file, \
                                create_new_repository,           \
                                load_repository
import tuf.client.updater
import tuf
import tuf.util
import tuf.keydb
import tuf.roledb
import tuf.conf
import fasteners
from dxf import DXFBase, DXF, hash_file, hash_bytes
import dxf.exceptions
from dtuf import exceptions

def _is_metadata_file(alias):
    return alias.endswith('root.json') or \
           alias.endswith('targets.json') or \
           alias.endswith('snapshot.json') or \
           alias.endswith('timestamp.json')

_tuf_lock = threading.Lock()
_updater_dxf = None
_updater_progress = None

def _tuf_clear():
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

def _master_repo_locked(f):
    def locked(self, *args, **kwargs):
        # pylint: disable=protected-access
        return _locked(self._master_repo_lock, None, f, self, *args, **kwargs)
    return locked

def _copy_repo_locked(f):
    def locked(self, args, **kwargs):
        # pylint: disable=global-statement,protected-access
        def setup():
            global _updater_dxf
            _updater_dxf = self._dxf
            tuf.conf.repository_directory = self._copy_repo_dir
        return _locked(self._copy_repo_lock, setup, f, self, *args, **kwargs)
    return locked

def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
    _, alias = urlparse.urlparse(url).path.split('//')
    temp_file = tuf.util.TempFile()
    try:
        if _is_metadata_file(alias):
            dgst = _updater_dxf.get_alias(alias)[0]
        else:
            dgst = alias[0:alias.find('.')]
        n = 0
        it, size = _updater_dxf.pull_blob(dgst, size=True)
        for chunk in it:
            temp_file.write(chunk)
            if _updater_progress:
                _updater_progress(dgst, chunk, size)
            n += len(chunk)
            if STRICT_REQUIRED_LENGTH and (n > required_length):
                break
        # pylint: disable=protected-access
        tuf.download._check_downloaded_length(
            n, required_length, STRICT_REQUIRED_LENGTH=STRICT_REQUIRED_LENGTH)
        return temp_file
    except:
        temp_file.close_temp_file()
        raise

# pylint: disable=protected-access
tuf.download._download_file = _download_file

def _strip_consistent_target_digest(filename):
    dirname, basename = path.split(filename)
    return path.join(dirname, basename[basename.find('.') + 1:])

class DTufBase(object):
    def _wrap_auth(self, auth=None):
        return lambda dxf_obj, response: auth(self, response) if auth else None

    def __init__(self, host, auth=None, insecure=False):
        self._dxf = DXFBase(host, self._wrap_auth(auth), insecure)

    @property
    def token(self):
        return self._dxf.token

    @token.setter
    def token(self, value):
        self._dxf.token = value

    def auth_by_password(self, username, password, actions=None, response=None):
        return self._dxf.auth_by_password(username, password, actions, response)

    def list_repos(self):
        return self._dxf.list_repos()

class DTufCommon(DTufBase):
    # pylint: disable=too-many-arguments,super-init-not-called
    def __init__(self, host, repo, repos_root=None, auth=None, insecure=False):
        self._dxf = DXF(host, repo, self._wrap_auth(auth), insecure)
        self._repo_root = path.join(repos_root if repos_root else getcwd(), repo)

# pylint: disable=too-many-instance-attributes
class DTufMaster(DTufCommon):
    # pylint: disable=too-many-arguments
    def __init__(self, host, repo, repos_root=None, auth=None, insecure=False,
                 root_lifetime=None, targets_lifetime=None,
                 snapshot_lifetime=None, timestamp_lifetime=None):
        super(DTufMaster, self).__init__(host, repo, repos_root, auth, insecure)
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
        if password is None:
            print('generating root key...')
        generate_and_write_rsa_keypair(self._root_key_file, password=password)

    @_master_repo_locked
    def create_metadata_keys(self,
                             targets_key_password=None,
                             snapshot_key_password=None,
                             timestamp_key_password=None):
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

    @_master_repo_locked
    def create_metadata(self,
                        root_key_password=None,
                        targets_key_password=None,
                        snapshot_key_password=None,
                        timestamp_key_password=None):
        # Import root key
        public_root_key = import_rsa_publickey_from_file(
            self._root_key_file + '.pub')
        if root_key_password is None:
            print('importing root key...')
        private_root_key = import_rsa_privatekey_from_file(
            self._root_key_file,
            root_key_password)

        # Create repository object and load root key
        repository = create_new_repository(self._master_repo_dir)
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

        # Create metadata
        repository.write(consistent_snapshot=True)

    @_master_repo_locked
    def push_blobs(self, alias, *filename_or_alias_list, **kwargs):
        progress = kwargs.get('progress')
        if _is_metadata_file(alias):
            raise exceptions.DTufReservedAliasError(alias)
        dgsts = []
        for filename_or_alias in filename_or_alias_list:
            if filename_or_alias.startswith('@'):
                with open(path.join(self._master_targets_dir,
                                    filename_or_alias[1:]), 'rb') as f:
                    manifest = f.read()
                dgsts += self._dxf.get_alias(manifest=manifest, verify=False)
            else:
                dgsts.append(self._dxf.push_blob(filename_or_alias, progress))
        manifest = self._dxf.make_unsigned_manifest(alias, *dgsts)
        manifest_filename = path.join(self._master_targets_dir, alias)
        with open(manifest_filename, 'wb') as f:
            f.write(manifest)
        self._dxf.push_blob(manifest_filename, progress)

    @_master_repo_locked
    def del_blobs(self, alias):
        manifest_filename = path.join(self._master_targets_dir, alias)
        with open(manifest_filename, 'rb') as f:
            manifest = f.read()
        manifest_dgst = hash_bytes(manifest)
        remove(manifest_filename)
        for dgst in self._dxf.get_alias(manifest=manifest, verify=False):
            self._dxf.del_blob(dgst)
        self._dxf.del_blob(manifest_dgst)

    @_master_repo_locked
    def push_metadata(self,
                      targets_key_password=None,
                      snapshot_key_password=None,
                      timestamp_key_password=None,
                      progress=None):
        # Load repository object
        repository = load_repository(self._master_repo_dir)
        #  pylint: disable=no-member

        # Update targets
        repository.targets.clear_targets()
        repository.targets.add_targets([
            _strip_consistent_target_digest(f)
            for f in repository.get_filepaths_in_directory(self._master_targets_dir)])

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

        # Get files in metadata directory
        old_files = dict([(f, True) for f in listdir(self._master_staged_dir)])

        # Update metadata
        repository.write(consistent_snapshot=True)

        # Work out which files have been added
        new_files = [f for f in listdir(self._master_staged_dir) if f not in old_files]

        # root.json and timestamp.json versions without hash prefix
        if 'root.json' not in new_files:
            new_files.append('root.json')
        if 'timestamp.json' not in new_files:
            new_files.append('timestamp.json')

        # Upload metadata
        for f in new_files:
            dgst = self._dxf.push_blob(path.join(self._master_staged_dir, f),
                                       progress)
            self._dxf.set_alias(f, dgst)

    @_master_repo_locked
    def list_aliases(self):
        repository = load_repository(self._master_repo_dir)
        #  pylint: disable=no-member
        return repository.targets.target_files()

class DTufCopy(DTufCommon):
    # pylint: disable=too-many-arguments
    def __init__(self, host, repo, repos_root=None, auth=None, insecure=False):
        super(DTufCopy, self).__init__(host, repo, repos_root, auth, insecure)
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
                for chunk in it:
                    if progress:
                        progress(dgst, chunk, size)
                    temp_file.write(chunk)
                metadata = temp_file.read()
                metadata_signable = json.loads(metadata)
                tuf.formats.check_signable_object_format(metadata_signable)
                tuf.client.updater.Updater._ensure_not_expired.__func__(
                    None, metadata_signable['signed'], 'root')
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
                    raise tuf.BadSignatureError('root')
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
        updater.remove_obsolete_targets(self._copy_targets_dir)
        return [t['filepath'][1:] for t in updated_targets]

    @_copy_repo_locked
    def _get_digests(self, alias, sizes=False):
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        target = updater.target(alias)
        updater.download_target(target, self._copy_targets_dir)
        with open(path.join(self._copy_targets_dir, alias), 'rb') as f:
            manifest = f.read()
        return self._dxf.get_alias(manifest=manifest, verify=False, sizes=sizes)

    def pull_blobs(self, alias, digests_and_sizes=False):
        return [(it, dgst, size) if digests_and_sizes else it
                for dgst in self._get_digests(alias)
                for it, size in self._dxf.pull_blob(dgst,
                                                    size=digests_and_sizes)]

    def blob_sizes(self, alias):
        return [size for _, size in self._get_digests(alias, sizes=True)]

    def check_blobs(self, alias, *filenames):
        alias_dgsts = self._get_digests(alias)
        file_dgsts = [hash_file(filename) for filename in filenames]
        if file_dgsts != alias_dgsts:
            raise dxf.exceptions.DXFDigestMismatchError(file_dgsts, alias_dgsts)

    @_copy_repo_locked
    def list_aliases(self):
        updater = tuf.client.updater.Updater('updater',
                                             self._repository_mirrors)
        return [t['filepath'][1:] for t in updater.all_targets()]
