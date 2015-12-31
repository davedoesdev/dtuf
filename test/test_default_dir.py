import pytest
import dtuf

def test_default_dir(tmpdir):
    # pylint: disable=no-member
    assert not tmpdir.join('dtuf_repos').exists()
    with tmpdir.as_cwd():
        dtuf.DTufMaster('localhost:5000', pytest.repo).create_root_key(pytest.root_key_password)
    assert tmpdir.join('dtuf_repos').exists()
