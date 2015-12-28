import os
import pytest
import dtuf.main

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

# bad_args
# not_found
# reset_keys
# del_target
# put run_test target in Makefile back
