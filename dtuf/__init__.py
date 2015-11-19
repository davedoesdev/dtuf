from os import path, getcwd, remove, makedirs
import json
from tuf.repository_tool import *
import tuf.client.updater
from datetime import datetime, timedelta
from dxf import DXF
import tuf
import tuf.util
import urlparse
import threading
from exceptions import *

_metadata_files = ['root.json',
                   'targets.json',
                   'snapshot.json',
                   'timestamp.json']

_updater_dxf_lock = threading.Lock()
_updater_dxf = None # tuf has global config :-(

def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
    _, alias = urlparse.urlparse(url).path.split('//')
    temp_file = tuf.util.TempFile()
    try:
        if alias in _metadata_files:
            dgst = _updater_dxf.get_alias(alias)[0]
            n = 0
            for chunk in _updater_dxf.pull_blob(dgst):
                temp_file.write(chunk)
                n += len(chunk)
                if STRICT_REQUIRED_LENGTH and (n > required_length):
                    break
        else:
            manifest = _updater_dxf.get_alias(alias,
                                              return_unsigned_manifest=True)
            temp_file.write(manifest)
            n = len(manifest)
    except:
        temp_file.close_temp_file()
        raise
    tuf.download._check_downloaded_length(
            n, required_length, STRICT_REQUIRED_LENGTH=STRICT_REQUIRED_LENGTH)
    return temp_file

tuf.download._download_file = _download_file

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

    def auth_by_password(self, username, password, actions=[], response=None):
        return self._dxf.auth_by_password(username, password, actions, response)

    def list_repos(self):
        return self._dxf.list_repos()

class DTuf(DTufBase):
    def __init__(self, host, repo, repos_root=None, auth=None, insecure=False):
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

    def create_root_key(self, password=None):
        if password is None:
            print 'generating root key...'
        generate_and_write_rsa_keypair(self._root_key_file, password=password)

    def create_metadata_keys(self,
                             targets_key_password=None,
                             snapshot_key_password=None,
                             timestamp_key_password=None):
        if targets_key_password is None:
            print 'generating targets key...'
        generate_and_write_rsa_keypair(self._targets_key_file,
                                       password=targets_key_password)
        if snapshot_key_password is None:
            print 'generating snapshot key...'
        generate_and_write_rsa_keypair(self._snapshot_key_file,
                                       password=snapshot_key_password)
        if timestamp_key_password is None:
            print 'generating timestamp key...'
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
            print 'importing root key...'
        private_root_key = import_rsa_privatekey_from_file(
                                    self._root_key_file,
                                    root_key_password)

        # Create repository object and load root key
        repository = create_new_repository(self._master_repo_dir)
        repository.root.add_verification_key(public_root_key)
        repository.root.load_signing_key(private_root_key)
                
        # Add targets key to repository
        public_targets_key = import_rsa_publickey_from_file(
                                    self._targets_key_file + '.pub')
        if targets_key_password is None:
            print 'importing targets key...'
        private_targets_key = import_rsa_privatekey_from_file(
                                    self._targets_key_file,
                                    targets_key_password)
        repository.targets.add_verification_key(public_targets_key)
        repository.targets.load_signing_key(private_targets_key)

        # Add snapshot key to repository
        public_snapshot_key = import_rsa_publickey_from_file(
                                    self._snapshot_key_file + '.pub')
        if snapshot_key_password is None:
            print 'importing snapshot key...'
        private_snapshot_key = import_rsa_privatekey_from_file(
                                    self._snapshot_key_file,
                                    snapshot_key_password)
        repository.snapshot.add_verification_key(public_snapshot_key)
        repository.snapshot.load_signing_key(private_snapshot_key)

        # Add timestamp key to repository
        public_timestamp_key = import_rsa_publickey_from_file(
                                    self._timestamp_key_file + '.pub')
        if timestamp_key_password is None:
            print 'importing timestamp key...'
        private_timestamp_key = import_rsa_privatekey_from_file(
                                    self._timestamp_key_file,
                                    timestamp_key_password)
        repository.timestamp.add_verification_key(public_timestamp_key)
        repository.timestamp.load_signing_key(private_timestamp_key)

        # Create metadata
        repository.write()

    def push_blob(self, filename_or_alias, alias):
        if alias in _metadata_files:
            raise DTufReservedAliasError(alias)
        if filename_or_alias.startswith('@'):
            dgst = self._dxf.get_alias(filename_or_alias[1:])[0]
        else:
            dgst = self._dxf.push_blob(filename_or_alias)
        manifest = self._dxf.set_alias(alias, dgst, return_unsigned_manifest=True)
        with open(path.join(self._master_targets_dir, alias), 'wb') as f:
            f.write(manifest)

    def del_blob(self, alias):
        remove(path.join(self._master_targets_dir, alias))
        for dgst in self._dxf.del_alias(alias):
            self._dxf.del_blob(dgst)

    def push_metadata(self,
                      targets_key_password=None,
                      snapshot_key_password=None,
                      timestamp_key_password=None):
        # Load repository object
        repository = load_repository(self._master_repo_dir)

        # Update targets
        repository.targets.clear_targets()
        repository.targets.add_targets(repository.get_filepaths_in_directory(
                                            self._master_targets_dir))

        # Update expirations
        repository.targets.expiration = datetime.now() + \
                                        timedelta(seconds=TARGETS_EXPIRATION)
        repository.snapshot.expiration = datetime.now() + \
                                         timedelta(seconds=SNAPSHOT_EXPIRATION)
        repository.timestamp.expiration = datetime.now() + \
                                          timedelta(seconds=TIMESTAMP_EXPIRATION)

        # Load targets key
        if targets_key_password is None:
            print 'importing targets key...'
        private_targets_key = import_rsa_privatekey_from_file(
                                    self._targets_key_file,
                                    targets_key_password)
        repository.targets.load_signing_key(private_targets_key)

        # Load snapshot key
        if snapshot_key_password is None:
            print 'importing snapshot key...'
        private_snapshot_key = import_rsa_privatekey_from_file(
                                    self._snapshot_key_file,
                                    snapshot_key_password)
        repository.snapshot.load_signing_key(private_snapshot_key)

        # Load timestamp key
        if timestamp_key_password is None:
            print 'importing timestamp key...'
        private_timestamp_key = import_rsa_privatekey_from_file(
                                    self._timestamp_key_file,
                                    timestamp_key_password)
        repository.timestamp.load_signing_key(private_timestamp_key)

        # Update metadata
        repository.write()

        # Upload metadata
        for f in _metadata_files:
            dgst = self._dxf.push_blob(path.join(self._master_staged_dir, f))
            self._dxf.set_alias(f, dgst)

    def pull_metadata(self, root_public_key=None):
        with _updater_dxf_lock:
            for d in ['current', 'previous']:
                try:
                    makedirs(path.join(self._copy_repo_dir, 'metadata', d))
                except OSError as exception:
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
                _updater_dxf = None
        
    def pull_blob(self, alias):
        with _updater_dxf_lock:
            tuf.conf.repository_directory = self._copy_repo_dir
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
                _updater_dxf = None
        dgsts = self._dxf.get_alias(manifest=manifest, verify=False)
        for dgst in dgsts:
            for chunk in self._dxf.pull_blob(dgst):
                yield chunk

    def list_aliases(self):
        with _updater_dxf_lock:
            tuf.conf.repository_directory = self._copy_repo_dir
            global _updater_dxf
            _updater_dxf = self._dxf
            try:
                updater = tuf.client.updater.Updater('updater',
                                                     self._repository_mirrors)
                return [t['filepath'][1:] for t in updater.all_targets()]
            finally:
                _updater_dxf = None
