# pylint: disable=no-member
import os
from os import path
import sys
import hashlib
import shutil
import errno
import time
from datetime import datetime, timedelta, tzinfo
from io import BytesIO
import requests
import pytest
import tuf
import tqdm
import iso8601
import dxf.exceptions
import dtuf.main

class _UTC(tzinfo):
    # pylint: disable=unused-argument
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)

utc = _UTC()

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

def test_push_target_progress(dtuf_main, capfd):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['push-target', pytest.repo, 'hello2', pytest.blob3_file], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob3_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob3_size) + "/" + str(pytest.blob3_size) in err
    target_file = path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'master', 'repository', 'targets', 'hello2')
    target_dgst = dxf.hash_file(target_file)
    target_size = path.getsize(target_file)
    assert target_dgst[0:8] in err
    assert " " + str(target_size) + "/" + str(target_size) in err

def test_see_push_target_progress(dtuf_main, monkeypatch):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    orig_tqdm = tqdm.tqdm
    def new_tqdm(*args, **kwargs):
        tqdm_obj = orig_tqdm(*args, **kwargs)
        class TQDM(object):
            # pylint: disable=no-self-use
            def update(self, n):
                tqdm_obj.update(n)
                time.sleep(0.025)
            def close(self):
                tqdm_obj.close()
            @property
            def n(self):
                return tqdm_obj.n
            @property
            def total(self):
                return tqdm_obj.total
        return TQDM()
    monkeypatch.setattr(tqdm, 'tqdm', new_tqdm)
    assert dtuf.main.doit(['push-target', pytest.repo, 'hello2', pytest.blob4_file], environ) == 0

def test_push_metadata(dtuf_main):
    environ = {
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['push-metadata', pytest.repo], environ) == 0

def test_push_metadata_progress(dtuf_main, capfd):
    environ = {
        'DTUF_PROGRESS': '1',
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['push-metadata', pytest.repo], environ) == 0
    _, err = capfd.readouterr()
    #assert pytest.blob3_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    metadata_file = path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'master', 'repository', 'metadata.staged', 'timestamp.json')
    metadata_dgst = dxf.hash_file(metadata_file)
    metadata_size = path.getsize(metadata_file)
    assert metadata_dgst[0:8] in err
    assert " " + str(metadata_size) + "/" + str(metadata_size) in err

def test_see_push_metadata_progress(dtuf_main):
    environ = {
        'DTUF_PROGRESS': '1',
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['push-metadata', pytest.repo], environ) == 0

def _copy_metadata_exists(dtuf_main, metadata):
    return path.exists(path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'copy', 'repository', 'metadata', 'current', metadata + '.json'))

def test_list_master_targets(dtuf_main, capsys):
    assert dtuf.main.doit(['list-master-targets', pytest.repo], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'hello2', 'there']
    assert err == ""

def _pull_metadata_with_master_public_root_key(dtuf_main):
    return dtuf.main.doit(['pull-metadata', pytest.repo, path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'master', 'keys', 'root_key.pub')], dtuf_main)

def test_pull_metadata(dtuf_main, monkeypatch, capsys):
    exists = _copy_metadata_exists(dtuf_main, 'root')
    with pytest.raises(tuf.NoWorkingMirrorError if exists else tuf.RepositoryError) as ex:
        dtuf.main.doit(['pull-metadata', pytest.repo], dtuf_main)
    if exists:
        # Because of test_reset_keys below, the copy's current metadata will
        # have a higher version number than the newly-created and pushed master
        # metadata. That will generate a ReplayedMetadata error.
        for ex2 in ex.value.mirror_errors.values():
            assert isinstance(ex2, tuf.ReplayedMetadataError)
            assert ex2.metadata_role == 'timestamp'
            assert ex2.previous_version == 4 # create=1, push=2
            assert ex2.current_version == 17
        dir_name = path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'copy', 'repository', 'metadata', 'current')
        assert dir_name.startswith('/tmp/') # check what we're about to remove!
        shutil.rmtree(dir_name)
    else:
        assert str(ex.value) == 'No root of trust! Could not find the "root.json" file.'
    capsys.readouterr()
    # pylint: disable=too-few-public-methods
    class FakeStdin(object):
        # pylint: disable=no-self-use
        def read(self):
            return pytest.make_dummy_root_pub_key()
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    with pytest.raises(tuf.CryptoError):
        assert dtuf.main.doit(['pull-metadata', pytest.repo, '-'], dtuf_main) == 0
    capsys.readouterr()
    assert _pull_metadata_with_master_public_root_key(dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == \
        (['', 'hello', 'hello2'] if exists else ['', 'foobar', 'hello', 'hello2', 'there'])
    assert err == ""

def test_pull_metadata_progress(dtuf_main, capfd):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['pull-metadata', pytest.repo], environ) == 0
    _, err = capfd.readouterr()
    assert " 0%" in err
    assert " 100%" in err
    metadata_file = path.join(dtuf_main['TEST_REPO_DIR'], pytest.repo, 'copy', 'repository', 'metadata', 'current', 'timestamp.json')
    metadata_dgst = dxf.hash_file(metadata_file)
    metadata_size = path.getsize(metadata_file)
    assert metadata_dgst[0:8] in err
    assert " " + str(metadata_size) + "/" + str(metadata_size) in err

def test_see_pull_metadata_progress(dtuf_main):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['pull-metadata', pytest.repo], environ) == 0

# pylint: disable=too-many-arguments
def _pull_target(dtuf_main, target, expected_dgsts, expected_sizes, get_info, capfd):
    environ = {'DTUF_BLOB_INFO': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['pull-target', pytest.repo, target], environ if get_info else dtuf_main) == 0
    # pylint: disable=protected-access
    encoding = capfd._capture.out.tmpfile.encoding
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    if get_info:
        outs = BytesIO(out)
        for i, size in enumerate(expected_sizes):
            assert outs.readline() == expected_dgsts[i].encode('utf-8') + b' ' + str(size).encode('utf-8') + b'\n'
            sha256 = hashlib.sha256()
            sha256.update(outs.read(size))
            assert 'sha256:' + sha256.hexdigest() == expected_dgsts[i]
        assert len(outs.read()) == 0
    else:
        pos = 0
        for i, size in enumerate(expected_sizes):
            sha256 = hashlib.sha256()
            sha256.update(out[pos:pos + size])
            pos += size
            assert 'sha256:' + sha256.hexdigest() == expected_dgsts[i]
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

def test_pull_target_progress(dtuf_main, capfd):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    assert dtuf.main.doit(['pull-target', pytest.repo, 'hello'], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob1_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob1_size) + "/" + str(pytest.blob1_size) in err

def test_see_pull_target_progress(dtuf_main, monkeypatch):
    environ = {'DTUF_PROGRESS': '1'}
    environ.update(dtuf_main)
    # pylint: disable=too-few-public-methods
    class FakeStdout(object):
        # pylint: disable=no-self-use
        def write(self, _):
            time.sleep(0.05)
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    assert dtuf.main.doit(['pull-target', pytest.repo, 'hello'], environ) == 0

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
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'hello2', 'there']
    assert err == ""

def test_list_repos(dtuf_main, capsys):
    assert dtuf.main.doit(['list-repos'], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.repo + os.linesep
    assert err == ""

def test_auth(dtuf_main, capsys):
    if dtuf_main['DTUF_INSECURE'] == '1':
        environ = {
            'DTUF_USERNAME': pytest.username,
            'DTUF_PASSWORD': pytest.password
        }
        environ.update(dtuf_main)
        with pytest.raises(dxf.exceptions.DXFAuthInsecureError):
            dtuf.main.doit(['auth', pytest.repo], environ)
    elif dtuf_main['TEST_DO_TOKEN']:
        assert dtuf.main.doit(['auth', pytest.repo, '*'], dtuf_main) == 0
        token, err = capsys.readouterr()
        assert token
        assert err == ""
        environ = {}
        environ.update(dtuf_main)
        del environ['DTUF_USERNAME']
        del environ['DTUF_PASSWORD']
        assert dtuf.main.doit(['blob-sizes', pytest.repo, 'hello'], environ) == errno.EACCES
        out, err = capsys.readouterr()
        assert out == ""
        environ['DTUF_TOKEN'] = token.strip()
        assert dtuf.main.doit(['blob-sizes', pytest.repo, 'hello'], environ) == 0
        out, err = capsys.readouterr()
        assert out == str(pytest.blob1_size) + os.linesep
        assert err == ""
    else:
        assert dtuf.main.doit(['auth', pytest.repo], dtuf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""

def test_lifetime(dtuf_main, capsys):
    for role in ['TIMESTAMP', 'SNAPSHOT', 'TARGETS', 'ROOT']:
        environ = {
            'DTUF_ROOT_KEY_PASSWORD': pytest.root_key_password,
            'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
            'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
            'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password,
            'DTUF_' + role + '_LIFETIME': '1s'
        }
        environ.update(dtuf_main)
        assert dtuf.main.doit(['reset-keys', pytest.repo], environ) == 0
        test_push_metadata(environ)
        time.sleep(2)
        with pytest.raises(tuf.NoWorkingMirrorError) as ex:
            dtuf.main.doit(['pull-metadata', pytest.repo], dtuf_main)
        for ex2 in ex.value.mirror_errors.values():
            assert isinstance(ex2, tuf.ExpiredMetadataError)
            assert str(ex2).startswith("Metadata u'" + role.lower() + "' expired") or \
                   str(ex2).startswith("Metadata '" + role.lower() + "' expired")
        capsys.readouterr()
        dtuf.main.doit(['get-master-expirations', pytest.repo], dtuf_main)
        out, err = capsys.readouterr()
        assert err == ""
        e = {}
        for l in out.split(os.linesep):
            if l:
                f = l.split(': ')
                e[f[0]] = iso8601.parse_date(f[1])
        assert len(e) == 4
        now = datetime.now(utc)
        for r in ['timestamp', 'snapshot', 'targets', 'root']:
            if r.upper() == role:
                assert e[r] < now
            else:
                assert e[r] > now

def test_del_target(dtuf_main, capsys):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dtuf.main.doit(['del-target', pytest.repo, 'hello'], dtuf_main)
    assert ex.value.response.status_code == requests.codes.method_not_allowed
    # target file should have been removed but targets not rebuilt until push
    assert dtuf.main.doit(['list-master-targets', pytest.repo], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello', 'hello2', 'there']
    assert err == ""
    test_push_metadata(dtuf_main)
    assert dtuf.main.doit(['list-master-targets', pytest.repo], dtuf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'foobar', 'hello2', 'there']
    assert err == ""

def test_reset_keys(dtuf_main, capsys):
    # create new non-root keys
    test_create_root_key(dtuf_main)
    # reset repository keys
    environ = {
        'DTUF_ROOT_KEY_PASSWORD': pytest.root_key_password,
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['reset-keys', pytest.repo], environ) == 0
    # push metadata
    test_push_metadata(dtuf_main)
    # pull metadata
    # this will fail even though we didn't change the root key because root.json
    # has been updated (it stores the other public keys); unless we pass in
    # the root public key, we don't update root.json
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        dtuf.main.doit(['pull-metadata', pytest.repo], dtuf_main)
    for ex2 in ex.value.mirror_errors.values():
        assert isinstance(ex2, tuf.CryptoError)
    capsys.readouterr()
    # pull metadata again with public root key
    assert _pull_metadata_with_master_public_root_key(dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == "hello2" + os.linesep
    assert err == ""
    # create new root key
    test_create_root_key(dtuf_main)
    # reset repository keys
    environ = {
        'DTUF_ROOT_KEY_PASSWORD': pytest.root_key_password,
        'DTUF_TARGETS_KEY_PASSWORD': pytest.targets_key_password,
        'DTUF_SNAPSHOT_KEY_PASSWORD': pytest.snapshot_key_password,
        'DTUF_TIMESTAMP_KEY_PASSWORD': pytest.timestamp_key_password
    }
    environ.update(dtuf_main)
    assert dtuf.main.doit(['reset-keys', pytest.repo], environ) == 0
    # push metadata
    test_push_metadata(dtuf_main)
    # pull metadata
    # this will fail because root.json has been updated; unless we pass in the
    # root public key, we don't update root.json
    with pytest.raises(tuf.NoWorkingMirrorError) as ex:
        dtuf.main.doit(['pull-metadata', pytest.repo], dtuf_main)
    for ex2 in ex.value.mirror_errors.values():
        assert isinstance(ex2, tuf.CryptoError)
    capsys.readouterr()
    # pull metadata again with public root key
    assert _pull_metadata_with_master_public_root_key(dtuf_main) == 0
    out, err = capsys.readouterr()
    assert out == "hello2" + os.linesep
    assert err == ""
    dtuf.main.doit(['get-copy-expirations', pytest.repo], dtuf_main)
    out, err = capsys.readouterr()
    assert err == ""
    e = {}
    for l in out.split(os.linesep):
        if l:
            f = l.split(': ')
            e[f[0]] = iso8601.parse_date(f[1])
    assert len(e) == 4
    now = datetime.now(utc)
    for r in ['timestamp', 'snapshot', 'targets', 'root']:
        assert e[r] > now

def _num_args(dtuf_main, op, minimum, maximum, capsys):
    if minimum is not None:
        with pytest.raises(SystemExit):
            dtuf.main.doit([op, pytest.repo] + ['a'] * (minimum - 1), dtuf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too few arguments" in err
    if maximum is not None:
        with pytest.raises(SystemExit):
            dtuf.main.doit([op, pytest.repo] + ['a'] * (maximum + 1), dtuf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too many arguments" in err

def test_bad_args(dtuf_main, capsys):
    _num_args(dtuf_main, 'create-root-key', None, 0, capsys)
    _num_args(dtuf_main, 'create-metadata-keys', None, 0, capsys)
    _num_args(dtuf_main, 'create-metadata', None, 0, capsys)
    _num_args(dtuf_main, 'reset-keys', None, 0, capsys)
    _num_args(dtuf_main, 'push-target', 2, None, capsys)
    _num_args(dtuf_main, 'push-metadata', None, 0, capsys)
    _num_args(dtuf_main, 'list-master-targets', None, 0, capsys)
    _num_args(dtuf_main, 'get-master-expirations', None, 0, capsys)
    _num_args(dtuf_main, 'pull-metadata', None, 1, capsys)
    _num_args(dtuf_main, 'check-target', 2, None, capsys)
    _num_args(dtuf_main, 'list-copy-targets', None, 0, capsys)
    _num_args(dtuf_main, 'get-copy-expirations', None, 0, capsys)

def test_auth_host(dtuf_main):
    if dtuf_main['TEST_DO_TOKEN']:
        environ = {'DTUF_AUTH_HOST': 'localhost:5002'}
        environ.update(dtuf_main)
        with pytest.raises(requests.exceptions.ConnectionError):
            dtuf.main.doit(['list-repos'], environ)

# pylint: disable=unused-argument
def test_log(dtuf_main):
    assert path.exists('dtuf.log')
    assert not path.exists('tuf.log')
