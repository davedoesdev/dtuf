import hashlib
from os import path
import pytest
import tuf

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
#    _not_found(dtuf_objs, 'hello there')

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
    dtuf_objs.master.push_target('there', pytest.blob1_file)
    dtuf_objs.master.push_target('hello there', '@hello', pytest.blob2_file)

def test_push_metadata(dtuf_objs):
    dtuf_objs.master.push_metadata(pytest.targets_key_password,
                                   pytest.snapshot_key_password,
                                   pytest.timestamp_key_password)

def test_list_master_targets(dtuf_objs):
    assert sorted(dtuf_objs.master.list_targets()) == ['hello', 'hello there', 'there']

def test_pull_metadata(dtuf_objs):
    exists = _copy_metadata_exists(dtuf_objs, 'root')
    with pytest.raises(tuf.NoWorkingMirrorError if exists else tuf.RepositoryError):
        dtuf_objs.copy.pull_metadata()
    with open(path.join(dtuf_objs.repo_dir, pytest.repo, 'master', 'keys', 'root_key.pub'), 'rb') as f:
        assert sorted(dtuf_objs.copy.pull_metadata(f.read())) == \
            (['hello there', 'there'] if exists else ['hello', 'hello there', 'there'])
    assert _copy_metadata_exists(dtuf_objs, 'root')
    assert _copy_metadata_exists(dtuf_objs, 'targets')
    assert _copy_metadata_exists(dtuf_objs, 'snapshot')
    assert _copy_metadata_exists(dtuf_objs, 'timestamp')

def _pull_target(dtuf_objs, target, expected_dgsts, expected_sizes):
    its = dtuf_objs.copy.pull_target(target)
    for i, it in enumerate(its):
        sha256 = hashlib.sha256()
        for chunk in it:
            sha256.update(chunk)
        assert sha256.hexdigest() == expected_dgsts[i]

def test_pull_target(dtuf_objs):
    # test non-existent target
    _pull_target(dtuf_objs, 'hello', [pytest.blob1_hash], None)

# test digests and sizes
# test digest mismatch is thrown
# test updating target

# def test_del_target
