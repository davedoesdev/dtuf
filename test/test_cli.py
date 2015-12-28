import os
import sys
import pytest
import tuf
import dtuf.main
from os import path

def test_empty(dtuf_main, capsys):
    assert dtuf.main.doit(['list-repos'], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

def test_create_root_key(dtuf_main):
    environ = {'DTUF_ROOT_KEY_PASSWORD': pytest.root_key_password}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['create-root-key', pytest.repo], environ) == 0

def test_create_metadata_keys(dtuf_main):
    environ = {
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['create-metadata-keys', pytest.repo], environ) == 0

def test_create_metadata(dtuf_main):
    environ = {
        'DTUF_ROOT_KEY_PASSWORD': pytest.root_key_password,
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['create-metadata', pytest.repo], environ) == 0

def test_push_target(dtuf_main):
    assert dtuf.main.doit(['push-target', pytest.repo, 'hello', pytest.blob1_file], dtuf_main) == 0
    assert dtuf.main.doit(['push-target', pytest.repo, 'there', pytest.blob2_file], dtuf_main) == 0
    assert dtuf.main.doit(['push-target', pytest.repo, 'foobar', '@hello', pytest.blob2_file], dtuf_main) == 0

def test_push_metadata(dtuf_main):
    environ = {
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['push-metadata', pytest.repo], environ) == 0

def test_list_master_targets(dtuf_main, capsys):
    assert dtuf.main.doit(['list-master-targets', pytest.repo], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'there']
    assert err == ""

#def _copy_metadata_exists(dtuf_main, metadata):
#    return path.exists(path.join(dtuf_objs.repo_dir, pytest.repo, 'copy', 'repository', 'metadata', 'current', metadata + '.json'))

def _pull_metadata_with_master_public_root_key(dtuf_main):
    return dtuf.main.doit(['pull-metadata', pytest.repo, path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'master', 'keys', 'root_key.pub')], dtuf_main)

def test_pull_metadata(dtuf_main, monkeypatch, capsys):
    class FakeStdin(object):
        def read(self):
            return pytest.dummy_root_pub_key
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    with pytest.raises(tuf.CryptoError):
        assert dtuf.main.doit(['pull-metadata', pytest.repo, '-'], dtuf_main) == 0
    out, err = capsys.readouterr()
    _pull_metadata_with_master_public_root_key(dtuf_main)
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'there']
    assert err == ""

# bad_args
# not_found
# reset_keys
# del_target
# put run_test target in Makefile back
