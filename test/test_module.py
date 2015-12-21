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

def test_create_root_key(dtuf_master_obj):
    dtuf_master_obj.create_root_key(pytest.root_key_password)
    assert path.exists(path.join(dtuf_master_obj.test_repo_dir, pytest.repo, 'master', 'keys', 'root_key'))
    assert path.exists(path.join(dtuf_master_obj.test_repo_dir, pytest.repo, 'master', 'keys', 'root_key.pub'))
