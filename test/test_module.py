from os import path
import pytest
import tuf

def _not_found(dtuf_copy_obj, target):
    with pytest.raises(tuf.RepositoryError):
        dtuf_copy_obj.blob_sizes(target)

def test_not_found(dtuf_copy_obj):
    _not_found(dtuf_copy_obj, 'hello')
    _not_found(dtuf_copy_obj, 'there')
    _not_found(dtuf_copy_obj, 'hello there')

def _check_key_exists(dtuf_master_obj, key):
    assert path.exists(path.join(dtuf_master_obj.test_repo_dir, pytest.repo, 'master', 'keys', key + '_key'))
    assert path.exists(path.join(dtuf_master_obj.test_repo_dir, pytest.repo, 'master', 'keys', key + '_key.pub'))

def test_create_root_key(dtuf_master_obj):
    dtuf_master_obj.create_root_key(pytest.root_key_password)
    _check_key_exists(dtuf_master_obj, 'root')

def test_create_metadata_keys(dtuf_master_obj):
    dtuf_master_obj.create_metadata_keys(pytest.targets_key_password,
                                         pytest.snapshot_key_password,
                                         pytest.timestamp_key_password)
    _check_key_exists(dtuf_master_obj, 'targets')
    _check_key_exists(dtuf_master_obj, 'snapshot')
    _check_key_exists(dtuf_master_obj, 'timestamp')

def _check_metadata_exists(dtuf_master_obj, metadata):
    assert path.exists(path.join(dtuf_master_obj.test_repo_dir, pytest.repo, 'master', 'repository', 'metadata.staged', metadata + '.json'))

def test_create_metadata(dtuf_master_obj):
    dtuf_master_obj.create_metadata(pytest.root_key_password,
                                    pytest.targets_key_password,
                                    pytest.snapshot_key_password,
                                    pytest.timestamp_key_password)
    _check_metadata_exists(dtuf_master_obj, 'root')
    _check_metadata_exists(dtuf_master_obj, 'timestamp')

def test_push_target(dtuf_master_obj):
    dtuf_master_obj.push_target('hello', pytest.blob1_file)
    dtuf_master_obj.push_target('there', pytest.blob1_file)
    dtuf_master_obj.push_target('hello there', '@hello', pytest.blob2_file)

def test_push_metadata(dtuf_master_obj):
    dtuf_master_obj.push_metadata(pytest.targets_key_password,
                                  pytest.snapshot_key_password,
                                  pytest.timestamp_key_password)

def test_list_targets(dtuf_master_obj):
    assert sorted(dtuf_master_obj.list_targets()) == ['hello', 'hello there', 'there']

# def test_del_target
