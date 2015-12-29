import os
import sys
import hashlib
from StringIO import StringIO
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

def _copy_metadata_exists(dtuf_main, metadata):
    return path.exists(path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'copy', 'repository', 'metadata', 'current', metadata + '.json'))

def _pull_metadata_with_master_public_root_key(dtuf_main):
    return dtuf.main.doit(['pull-metadata', pytest.repo, path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'master', 'keys', 'root_key.pub')], dtuf_main)

def test_pull_metadata(dtuf_main, monkeypatch, capsys):
    exists = _copy_metadata_exists(dtuf_main, 'root')
    with pytest.raises(tuf.NoWorkingMirrorError if exists else tuf.RepositoryError) as ex:
        dtuf.main.doit(['pull-metadata', pytest.repo], dtuf_main)
    if exists:
        for ex2 in ex.value.mirror_errors.values():
            assert isinstance(ex2, tuf.CryptoError)
    else:
        assert ex.value.message == 'No root of trust! Could not find the "root.json" file.'
    capsys.readouterr()
    class FakeStdin(object):
        def read(self):
            return pytest.dummy_root_pub_key
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    with pytest.raises(tuf.CryptoError):
        assert dtuf.main.doit(['pull-metadata', pytest.repo, '-'], dtuf_main) == 0
    capsys.readouterr()
    _pull_metadata_with_master_public_root_key(dtuf_main)
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == \
        ([''] if exists else ['', 'foobar', 'hello', 'there'])
    assert err == ""

def _pull_target(dtuf_main, target, expected_dgsts, expected_sizes, get_info, capfd):
    environ = {'DTUF_BLOB_INFO': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['pull-target', pytest.repo, target], environ if get_info else dtuf_main) == 0
    encoding = capfd._capture.out.tmpfile.encoding
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    if get_info:
        outs = StringIO(out)
        for i, size in enumerate(expected_sizes):
            assert outs.readline() == expected_dgsts[i].encode('utf-8') + b' ' + str(size).encode('utf-8') + b'\n'
            sha256 = hashlib.sha256()
            sha256.update(outs.read(size))
            assert sha256.hexdigest() == expected_dgsts[i]
        assert len(outs.read()) == 0
    else:
        pos = 0
        for i, size in enumerate(expected_sizes):
            sha256 = hashlib.sha256()
            sha256.update(out[pos:pos + size])
            pos += size
            assert sha256.hexdigest() == expected_dgsts[i]
        assert pos == len(out)
    assert err == ""
    capfd._capture.out.tmpfile.encoding = encoding

def test_pull_target(dtuf_main, capfd):
    with pytest.raises(tuf.UnknownTargetError):
        dtuf.main.doit(['pull-target', pytest.repo, 'dummy'], dtuf_main)
    capfd.readouterr()
    for get_info in [False, True]:
        _pull_target(dtuf_main, 'hello', [pytest.blob1_hash], [pytest.blob1_size], get_info, capfd)
        _pull_target(dtuf_main, 'there', [pytest.blob2_hash], [pytest.blob2_size], get_info, capfd)
        _pull_target(dtuf_main, 'foobar', [pytest.blob1_hash, pytest.blob2_hash], [pytest.blob1_size, pytest.blob2_size], get_info, capfd)

def test_blob_sizes(dtuf_main, capsys):
    assert dtuf.main.doit(['blob-sizes', pytest.repo, 'hello', 'there', 'foobar'], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep + \
                  str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep
    assert err == ""

def test_check_target(dtuf_main):
    assert dtuf.main.doit(['check-target', pytest.repo, 'hello', pytest.blob1_file], dtuf_main) == 0
    assert dtuf.main.doit(['check-target', pytest.repo, 'there', pytest.blob2_file], dtuf_main) == 0
    assert dtuf.main.doit(['check-target', pytest.repo, 'foobar', pytest.blob1_file, pytest.blob2_file], dtuf_main) == 0

def test_list_copy_targets(dtuf_main, capsys):
    assert dtuf.main.doit(['list-copy-targets', pytest.repo], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'there']
    assert err == ""

def test_list_repos(dtuf_main, capsys):
    assert dtuf.main.doit(['list-repos'], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.repo + os.linesep
    assert err == ""

#def test_auth(dtuf_main, capsys):


# bad_args
# not_found
# reset_keys
# del_target
# put run_test target in Makefile back
# auth
# progress
