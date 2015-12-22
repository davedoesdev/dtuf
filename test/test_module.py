import hashlib
from os import path
import pytest
import tuf
import dxf.exceptions

def _check_key_exists(dtuf_objs, key):
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', key + '_key'))
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', key + '_key.pub'))

def _check_master_metadata_exists(dtuf_objs, metadata):
    assert path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'repository', 'metadata.staged', metadata + '.json'))

def _copy_metadata_exists(dtuf_objs, metadata):
    return path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'metadata', 'current', metadata + '.json'))

def _not_found(dtuf_objs, target):
    with pytest.raises(tuf.RepositoryError):
        dtuf_objs.copy.blob_sizes(target)

#def test_not_found(dtuf_objs):
#    _not_found(dtuf_objs, 'hello')
#    _not_found(dtuf_objs, 'there')
#    _not_found(dtuf_objs, 'foobar')

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

def test_push_metadata(dtuf_objs):
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)

def test_list_master_targets(dtuf_objs):
    assert sorted(dtuf_objs.master.list_targets()) == ['foobar', 'hello', 'there']

def test_pull_metadata(dtuf_objs):
    exists = _copy_metadata_exists(dtuf_objs, 'root')
    with pytest.raises(tuf.NoWorkingMirrorError if exists else tuf.RepositoryError):
        dtuf_objs.copy.pull_metadata()
    with open(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', 'root_key.pub'), 'rb') as f:
        assert sorted(dtuf_objs.copy.pull_metadata(f.read())) == \
            ([] if exists else ['foobar', 'hello', 'there'])
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
            assert sha256.hexdigest() == dgst
            assert n == size
    else:
        for i, it in enumerate(its):
            sha256 = hashlib.sha256()
            for chunk in it:
                sha256.update(chunk)
            assert sha256.hexdigest() == expected_dgsts[i]

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
            for chunk in it:
                pass
    finally:
        hashlib.sha256 = orig_sha256

def test_pull_target(dtuf_objs):
    with pytest.raises(tuf.UnknownTargetError):
        dtuf_objs.copy.pull_target('dummy')
    _pull_target(dtuf_objs, 'hello', [pytest.blob1_hash], None)
    _pull_target(dtuf_objs, 'there', [pytest.blob2_hash], None)
    _pull_target(dtuf_objs, 'foobar', [pytest.blob1_hash, pytest.blob2_hash], None)
    _pull_target(dtuf_objs, 'hello', [pytest.blob1_hash], [pytest.blob1_size])
    _pull_target(dtuf_objs, 'there', [pytest.blob2_hash], [pytest.blob2_size])
    _pull_target(dtuf_objs, 'foobar', [pytest.blob1_hash, pytest.blob2_hash], [pytest.blob1_size, pytest.blob2_size])
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        _dummy_pull_target(dtuf_objs, 'hello', 2)
    assert ex.value.got == hashlib.sha256().hexdigest()
    assert ex.value.expected == pytest.blob1_hash
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        _dummy_pull_target(dtuf_objs, 'hello', 1)
    for ex2 in ex.value.mirror_errors.values():
        assert ex2.got == hashlib.sha256().hexdigest()
        assert ex2.expected == dxf.hash_file(path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'targets', 'hello'))

# test updating target
# test_blob_sizes
# test_check_target
# test_list_copy_targets

# test_not_found above

# def test_del_target
