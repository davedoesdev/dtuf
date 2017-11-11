# pylint: disable=no-member
import hashlib
import shutil
from os import path
import requests
import pytest
import tuf
import dxf.exceptions
import dtuf.exceptions

def _check_key_exists(dtuf_objs, key):
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', key + '_key'))
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', key + '_key.pub'))

def _check_master_metadata_exists(dtuf_objs, metadata):
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'repository', 'metadata.staged', metadata + '.json'))

def _copy_metadata_exists(dtuf_objs, metadata):
    return path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'metadata', 'current', metadata + '.json'))

def test_not_found(dtuf_objs):
    exists = _copy_metadata_exists(dtuf_objs, 'root')
    for target in ['never added', 'hello']:
        with pytest.raises(tuf.UnknownTargetError if exists else tuf.RepositoryError) as ex:
            dtuf_objs.copy.blob_sizes(target)
    for target in ['there', 'foobar']:
        if exists:
            with pytest.raises(tuf.NoWorkingMirrorError) as ex:
                dtuf_objs.copy.blob_sizes(target)
            for ex2 in ex.value.mirror_errors.values():
                assert isinstance(ex2, requests.exceptions.HTTPError)
                assert ex2.response.status_code == requests.codes.not_found
        else:
            with pytest.raises(tuf.RepositoryError):
                dtuf_objs.copy.blob_sizes(target)

def test_create_root_key(dtuf_objs):
    dtuf_objs.master.create_root_key(pytest.root_key_password)
    _check_key_exists(dtuf_objs, 'root')

def test_create_metadata_keys(dtuf_objs):
    dtuf_objs.master.create_metadata_keys(pytest.targets_key_password,
                                          pytest.snapshot_key_password,
                                          pytest.timestamp_key_password)
    _check_key_exists(dtuf_objs, 'targets')
    _check_key_exists(dtuf_objs, 'snapshot')
    _check_key_exists(dtuf_objs, 'timestamp')

def test_create_metadata(dtuf_objs):
    dtuf_objs.master.create_metadata(pytest.root_key_password,
                                     pytest.targets_key_password,
                                     pytest.snapshot_key_password,
                                     pytest.timestamp_key_password)
    _check_master_metadata_exists(dtuf_objs, 'root')
    _check_master_metadata_exists(dtuf_objs, 'timestamp')

def test_push_target(dtuf_objs):
    dtuf_objs.master.push_target('hello', pytest.blob1_file)
    dtuf_objs.master.push_target('there', pytest.blob2_file)
    dtuf_objs.master.push_target('foobar', '@hello', pytest.blob2_file)

def _reserved_target(dtuf_objs, target):
    with pytest.raises(dtuf.exceptions.DTufReservedTargetError) as ex:
        dtuf_objs.master.push_target(target, '@hello')
    assert ex.value.target == target

def test_reserved_target(dtuf_objs):
    _reserved_target(dtuf_objs, 'root.json')
    _reserved_target(dtuf_objs, 'targets.json')
    _reserved_target(dtuf_objs, 'snapshot.json')
    _reserved_target(dtuf_objs, 'timestamp.json')
    target = hashlib.sha256().hexdigest() + '.hello'
    with pytest.raises(dtuf.exceptions.DTufReservedTargetError) as ex:
        dtuf_objs.master.push_target(target, '@hello')
    assert ex.value.target == target

def test_push_metadata(dtuf_objs):
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)

def test_list_master_targets(dtuf_objs):
    assert sorted(dtuf_objs.master.list_targets()) == ['foobar', 'hello', 'there']

def _pull_metadata_with_master_public_root_key(dtuf_objs):
    with open(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', 'root_key.pub'), 'rb') as f:
        return dtuf_objs.copy.pull_metadata(f.read().decode('utf-8'))

#@pytest.mark.onlytest
def test_pull_metadata(dtuf_objs):
    exists = _copy_metadata_exists(dtuf_objs, 'root')
    with pytest.raises(tuf.NoWorkingMirrorError if exists else tuf.RepositoryError) as ex:
        dtuf_objs.copy.pull_metadata()
    if exists:
        for ex2 in ex.value.mirror_errors.values():
            assert isinstance(ex2, tuf.ReplayedMetadataError)
            assert ex2.metadata_role == 'timestamp'
            assert ex2.previous_version == 2 # create=1, push=2
            assert ex2.current_version == 8
        # Because of test_update below, the copy's current metadata will have
        # a higher version number than the newly-created and pushed master
        # metadata. That will generate a ReplayedMetadata error.
        dir_name = path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'metadata', 'current')
        assert dir_name.startswith('/tmp/') # check what we're about to remove!
        shutil.rmtree(dir_name)
    else:
        assert str(ex.value) == 'No root of trust! Could not find the "root.json" file.'
    with pytest.raises(tuf.CryptoError):
        dtuf_objs.copy.pull_metadata(pytest.make_dummy_root_pub_key())
    assert sorted(_pull_metadata_with_master_public_root_key(dtuf_objs)) == \
        (['foobar', 'hello'] if exists else ['foobar', 'hello', 'there'])
    assert _copy_metadata_exists(dtuf_objs, 'root')
    assert _copy_metadata_exists(dtuf_objs, 'targets')
    assert _copy_metadata_exists(dtuf_objs, 'snapshot')
    assert _copy_metadata_exists(dtuf_objs, 'timestamp')

def _pull_target(dtuf_objs, target, expected_dgsts, expected_sizes):
    its = dtuf_objs.copy.pull_target(target, digests_and_sizes=bool(expected_sizes))
    if expected_sizes:
        for i, (it, dgst, size) in enumerate(its):
            assert dgst == expected_dgsts[i]
            assert size == expected_sizes[i]
            sha256 = hashlib.sha256()
            n = 0
            for chunk in it:
                sha256.update(chunk)
                n += len(chunk)
            assert 'sha256:' + sha256.hexdigest() == dgst
            assert n == size
    else:
        for i, it in enumerate(its):
            sha256 = hashlib.sha256()
            for chunk in it:
                sha256.update(chunk)
            assert 'sha256:' + sha256.hexdigest() == expected_dgsts[i]

def _dummy_pull_target(dtuf_objs, target, n):
    orig_sha256 = hashlib.sha256
    class DummySHA256(object):
        # pylint: disable=no-self-use
        def update(self, chunk):
            pass
        def hexdigest(self):
            return orig_sha256().hexdigest()
    i = [0]
    def sha256():
        i[0] += 1
        return DummySHA256() if i[0] == n else orig_sha256()
    hashlib.sha256 = sha256
    try:
        for it in dtuf_objs.copy.pull_target(target):
            for _ in it:
                pass
    finally:
        hashlib.sha256 = orig_sha256

def test_pull_target(dtuf_objs):
    with pytest.raises(tuf.UnknownTargetError):
        for _ in dtuf_objs.copy.pull_target('dummy'):
            pass
    _pull_target(dtuf_objs, 'hello', [pytest.blob1_hash], None)
    _pull_target(dtuf_objs, 'there', [pytest.blob2_hash], None)
    _pull_target(dtuf_objs, 'foobar', [pytest.blob1_hash, pytest.blob2_hash], None)
    _pull_target(dtuf_objs, 'hello', [pytest.blob1_hash], [pytest.blob1_size])
    _pull_target(dtuf_objs, 'there', [pytest.blob2_hash], [pytest.blob2_size])
    _pull_target(dtuf_objs, 'foobar', [pytest.blob1_hash, pytest.blob2_hash], [pytest.blob1_size, pytest.blob2_size])
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        _dummy_pull_target(dtuf_objs, 'hello', 2)
    assert ex.value.got == 'sha256:' + hashlib.sha256().hexdigest()
    assert ex.value.expected == pytest.blob1_hash
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        _dummy_pull_target(dtuf_objs, 'hello', 1)
    for ex2 in ex.value.mirror_errors.values():
        assert ex2.got == 'sha256:' + hashlib.sha256().hexdigest()
        assert ex2.expected == dxf.hash_file(path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'targets', 'hello'))

def test_update(dtuf_objs):
    dtuf_objs.master.push_target('foobar', '@there', '@foobar', pytest.blob3_file)
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)
    assert dtuf_objs.copy.pull_metadata() == ['foobar']
    _pull_target(dtuf_objs, 'foobar', [pytest.blob2_hash, pytest.blob1_hash, pytest.blob2_hash, pytest.blob3_hash], [pytest.blob2_size, pytest.blob1_size, pytest.blob2_size, pytest.blob3_size])

def test_blob_sizes(dtuf_objs):
    assert dtuf_objs.copy.blob_sizes('hello') == [pytest.blob1_size]
    assert dtuf_objs.copy.blob_sizes('there') == [pytest.blob2_size]
    assert dtuf_objs.copy.blob_sizes('foobar') == [pytest.blob2_size, pytest.blob1_size, pytest.blob2_size, pytest.blob3_size]

def test_check_target(dtuf_objs):
    dtuf_objs.copy.check_target('hello', pytest.blob1_file)
    dtuf_objs.copy.check_target('there', pytest.blob2_file)
    dtuf_objs.copy.check_target('foobar', pytest.blob2_file, pytest.blob1_file, pytest.blob2_file, pytest.blob3_file)
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        dtuf_objs.copy.check_target('hello', pytest.blob2_file)
    assert ex.value.got == pytest.blob2_hash
    assert ex.value.expected == pytest.blob1_hash
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        dtuf_objs.copy.check_target('foobar', pytest.blob1_file)
    assert ex.value.got == (pytest.blob1_file,)
    assert ex.value.expected == [pytest.blob2_hash, pytest.blob1_hash, pytest.blob2_hash, pytest.blob3_hash]

def _list_copy_targets(dtuf_copy_obj):
    assert sorted(dtuf_copy_obj.list_targets()) == ['foobar', 'hello', 'there']

def test_list_copy_targets(dtuf_objs):
    _list_copy_targets(dtuf_objs.copy)

def test_context_manager(dtuf_objs):
    with dtuf_objs.copy as dtuf_copy_obj:
        _list_copy_targets(dtuf_copy_obj)

def _auth(dtuf_objs, obj_type):
    obj = getattr(dtuf_objs, obj_type)
    # pylint: disable=protected-access
    if obj._dxf._insecure:
        with pytest.raises(dxf.exceptions.DXFAuthInsecureError):
            obj.authenticate(pytest.username, pytest.password)
    elif dtuf_objs.do_token:
        assert obj.authenticate(pytest.username, pytest.password, '*') == obj.token
        assert obj.token
    else:
        assert obj.authenticate(pytest.username, pytest.password) is None

def test_auth(dtuf_objs):
    _auth(dtuf_objs, 'master')
    _auth(dtuf_objs, 'copy')

def test_del_target(dtuf_objs):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dtuf_objs.master.del_target('hello')
    assert ex.value.response.status_code == requests.codes.method_not_allowed
    # target file should have been removed but targets not rebuilt until push
    assert sorted(dtuf_objs.master.list_targets()) == ['foobar', 'hello', 'there']
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)
    assert sorted(dtuf_objs.master.list_targets()) == ['foobar', 'there']

def test_reset_keys(dtuf_objs):
    # create new non-root keys
    dtuf_objs.master.create_metadata_keys(pytest.targets_key_password,
                                          pytest.snapshot_key_password,
                                          pytest.timestamp_key_password)
    # reset repository keys
    dtuf_objs.master.reset_keys(pytest.root_key_password,
                                pytest.targets_key_password,
                                pytest.snapshot_key_password,
                                pytest.timestamp_key_password)
    # push metadata
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)
    # pull metadata
    # this will fail even though we didn't change the root key because root.json
    # has been updated (it stores the other public keys); unless we pass in
    # the root public key, we don't update root.json
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        dtuf_objs.copy.pull_metadata()
    for ex2 in ex.value.mirror_errors.values():
        assert isinstance(ex2, tuf.CryptoError)
    # pull metadata again with public root key
    assert _pull_metadata_with_master_public_root_key(dtuf_objs) == []
    # create new root key
    dtuf_objs.master.create_root_key(pytest.root_key_password)
    # reset repository keys
    dtuf_objs.master.reset_keys(pytest.root_key_password,
                                pytest.targets_key_password,
                                pytest.snapshot_key_password,
                                pytest.timestamp_key_password)
    # push metadata
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)
    # pull metadata
    # this will fail because root.json has been updated; unless we pass in the
    # root public key, we don't update root.json
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        dtuf_objs.copy.pull_metadata()
    for ex2 in ex.value.mirror_errors.values():
        assert isinstance(ex2, tuf.CryptoError)
    # pull metadata again with public root key
    assert _pull_metadata_with_master_public_root_key(dtuf_objs) == []
