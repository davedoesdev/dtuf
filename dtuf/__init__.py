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
from dxf import DXFBase, DXF, hash_file, hash_bytes
import dxf.exceptions
from dtuf import exceptions

def _is_metadata_file(alias):
    return alias.endswith('root.json') or \
           alias.endswith('targets.json') or \
           alias.endswith('snapshot.json') or \
           alias.endswith('timestamp.json')

_updater_dxf_lock = threading.Lock()
_updater_dxf = None # tuf has global config :-(

def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
    _, alias = urlparse.urlparse(url).path.split('//')
    temp_file = tuf.util.TempFile()
    try:
        if _is_metadata_file(alias):
            dgst = _updater_dxf.get_alias(alias)[0]
        else:
            dgst = alias[0:alias.find('.')]
        n = 0
        for chunk in _updater_dxf.pull_blob(dgst):
            temp_file.write(chunk)
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

# pylint: disable=too-many-instance-attributes
class DTuf(DTufBase):
    # pylint: disable=too-many-arguments,super-init-not-called
    def __init__(self, host, repo, repos_root=None, auth=None, insecure=False,
                 root_lifetime=None, targets_lifetime=None,
                 snapshot_lifetime=None, timestamp_lifetime=None):
        self._dxf = DXF(host, repo, self._wrap_auth(auth), insecure)
        self._repo_root = path.join(repos_root if repos_root else getcwd(), repo)
        self._master_dir = path.join(self._repo_root, 'master')
        self._keys_dir = path.join(self._master_dir, 'keys')
        self._root_key_file = path.join(self._keys_dir, 'root_key')
        self._targets_key_file = path.join(self._keys_dir, 'targets_key')
        self._snapshot_key_file = path.join(self._keys_dir, 'snapshot_key')
        self._timestamp_key_file = path.join(self._keys_dir, 'timestamp_key')
        self._master_repo_dir = path.join(self._master_dir, 'repository')
        self._master_targets_dir = path.join(self._master_repo_dir, 'targets')
        self._master_staged_dir = path.join(self._master_repo_dir, 'metadata.staged')
        self._copy_dir = path.join(self._repo_root, 'copy')
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
        self._root_lifetime = timedelta(seconds=ROOT_EXPIRATION) \
            if root_lifetime is None else root_lifetime
        self._targets_lifetime = timedelta(seconds=TARGETS_EXPIRATION) \
            if targets_lifetime is None else targets_lifetime
        self._snapshot_lifetime = timedelta(seconds=SNAPSHOT_EXPIRATION) \
            if snapshot_lifetime is None else snapshot_lifetime
        self._timestamp_lifetime = timedelta(seconds=TIMESTAMP_EXPIRATION) \
            if timestamp_lifetime is None else timestamp_lifetime

    def create_root_key(self, password=None):
        if password is None:
            print('generating root key...')
        generate_and_write_rsa_keypair(self._root_key_file, password=password)

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

    def push_blob(self, filename_or_alias, alias):
        if _is_metadata_file(alias):
            raise exceptions.DTufReservedAliasError(alias)
        if filename_or_alias.startswith('@'):
            dgst = self._get_digest(filename_or_alias[1:])
        else:
            dgst = self._dxf.push_blob(filename_or_alias)
        manifest = self._dxf.make_unsigned_manifest(alias, dgst)
        manifest_filename = path.join(self._master_targets_dir, alias)
        with open(manifest_filename, 'wb') as f:
            f.write(manifest)
        self._dxf.push_blob(manifest_filename)

    def del_blob(self, alias):
        manifest_filename = path.join(self._master_targets_dir, alias)
        with open(manifest_filename, 'rb') as f:
            manifest = f.read()
        manifest_dgst = hash_bytes(manifest)
        remove(manifest_filename)
        for dgst in self._dxf.get_alias(manifest=manifest, verify=False):
            self._dxf.del_blob(dgst)
        self._dxf.del_blob(manifest_dgst)

    def push_metadata(self,
                      targets_key_password=None,
                      snapshot_key_password=None,
                      timestamp_key_password=None):
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
            dgst = self._dxf.push_blob(path.join(self._master_staged_dir, f))
            self._dxf.set_alias(f, dgst)

    def pull_metadata(self, root_public_key=None):
        with _updater_dxf_lock:
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
                    for chunk in self._dxf.pull_blob(dgst):
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
            tuf.conf.repository_directory = self._copy_repo_dir
            # pylint: disable=global-statement
            global _updater_dxf
            _updater_dxf = self._dxf
            try:
                updater = tuf.client.updater.Updater('updater',
                                                     self._repository_mirrors)
                updater.refresh(False)
                targets = updater.all_targets()
                updated_targets = updater.updated_targets(
                    targets, self._copy_targets_dir)
                updater.remove_obsolete_targets(self._copy_targets_dir)
                return [t['filepath'][1:] for t in updated_targets]
            finally:
                tuf.conf.repository_directory = None
                _updater_dxf = None

    def _get_digest(self, alias):
        with _updater_dxf_lock:
            tuf.conf.repository_directory = self._copy_repo_dir
            # pylint: disable=global-statement
            global _updater_dxf
            _updater_dxf = self._dxf
            try:
                updater = tuf.client.updater.Updater('updater',
                                                     self._repository_mirrors)
                target = updater.target(alias)
                updater.download_target(target, self._copy_targets_dir)
                with open(path.join(self._copy_targets_dir, alias), 'rb') as f:
                    manifest = f.read()
            finally:
                tuf.conf.repository_directory = None
                _updater_dxf = None
        dgsts = self._dxf.get_alias(manifest=manifest, verify=False)
        assert len(dgsts) == 1
        return dgsts[0]

    def pull_blob(self, alias):
        for chunk in self._dxf.pull_blob(self._get_digest(alias)):
            yield chunk

    def blob_size(self, alias):
        return self._dxf.blob_size(self._get_digest(alias))

    def check_blob(self, filename, alias):
        file_dgst = hash_file(filename)
        alias_dgst = self._get_digest(alias)
        if file_dgst != alias_dgst:
            raise dxf.exceptions.DXFDigestMismatchError(file_dgst, alias_dgst)

    def list_aliases(self):
        with _updater_dxf_lock:
            tuf.conf.repository_directory = self._copy_repo_dir
            # pylint: disable=global-statement
            global _updater_dxf
            _updater_dxf = self._dxf
            try:
                updater = tuf.client.updater.Updater('updater',
                                                     self._repository_mirrors)
                return [t['filepath'][1:] for t in updater.all_targets()]
            finally:
                tuf.conf.repository_directory = None
                _updater_dxf = None
