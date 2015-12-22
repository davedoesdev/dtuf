import os
import subprocess
import time
import tempfile
import shutil
import requests
import pytest
import dtuf
import dtuf.main

# From https://pytest.org/latest/example/simple.html#making-test-result-information-available-in-fixtures
# pylint: disable=no-member,unused-argument
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()
    if rep.failed:
        setattr(item.getparent(pytest.Module), 'rep_failed', True)

_here = os.path.join(os.path.dirname(__file__))
_fixture_dir = os.path.join(_here, 'fixtures')
_registry_dir = os.path.join(_here, 'registry')
_auth_dir = os.path.join(_here, 'auth')
_remove_container = os.path.join(_here, 'remove_container.sh')

DEVNULL = open(os.devnull, 'wb')

def pytest_namespace():
    return {
        'blob1_file': os.path.join(_fixture_dir, 'blob1'),
        'blob2_file': os.path.join(_fixture_dir, 'blob2'),
        'blob3_file': os.path.join(_fixture_dir, 'blob3'),
        'blob4_file': os.path.join(_fixture_dir, 'blob4'),

        'blob1_hash': os.environ['HASH1'],
        'blob2_hash': os.environ['HASH2'],
        'blob3_hash': os.environ['HASH3'],
        'blob4_hash': os.environ['HASH4'],

        'blob1_size': 1 * 1024 * 1024,
        'blob2_size': 2 * 1024 * 1024,
        'blob3_size': 2 * 1024 * 1024,
        'blob4_size': 2 * 1024 * 1024,

        'username': 'fred',
        'password': '!WordPass0$',

        'repo': 'foo/bar',

        'root_key_password': 'Dummypw1',
        'targets_key_password': 'Dummypw2',
        'snapshot_key_password': 'Dummypw3',
        'timestamp_key_password': 'Dummypw4'
    }

@pytest.fixture(scope='module')
def repo_dir(request):
    dir_name = tempfile.mkdtemp() 
    # Be ultra cautious because we'll be doing rm -rf on this directory
    assert dir_name.startswith('/tmp/')
    def cleanup():
        shutil.rmtree(dir_name)
    request.addfinalizer(cleanup)
    return dir_name

def _auth(dtuf_obj, response):
    dtuf_obj.auth_by_password(pytest.username, pytest.password, response=response)

def _setup_fixture(request):
    setattr(request.node, 'rep_failed', False)
    def cleanup():
        if getattr(request.node, 'rep_failed', False):
            subprocess.call(['docker', 'logs', 'dtuf_registry'])
            subprocess.call(['docker', 'logs', 'dtuf_auth'])
        subprocess.call([_remove_container, 'dtuf_registry'])
        subprocess.call([_remove_container, 'dtuf_auth'])
    request.addfinalizer(cleanup)
    cleanup()
    cmd = ['docker', 'run', '-d', '-p', '5000:5000', '--name', 'dtuf_registry']
    auth, do_token = request.param
    if auth:
        cmd += ['-v', _registry_dir + ':/registry',
                '-v', _auth_dir + ':/auth',
                '-e', 'REGISTRY_HTTP_TLS_CERTIFICATE=/registry/registry.pem',
                '-e', 'REGISTRY_HTTP_TLS_KEY=/registry/registry.key']
        if do_token:
            # Thanks to https://the.binbashtheory.com/creating-private-docker-registry-2-0-with-token-authentication-service/
            cmd += ['-e', 'REGISTRY_AUTH=token',
                    '-e', 'REGISTRY_AUTH_TOKEN_REALM=https://localhost:5001/auth',
                    '-e', 'REGISTRY_AUTH_TOKEN_SERVICE=Docker registry',
                    '-e', 'REGISTRY_AUTH_TOKEN_ISSUER=Auth Service',
                    '-e', 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/auth/auth.pem']
            cmd2 = ['docker', 'run', '-d', '-p', '5001:5001',
                    '--name', 'dtuf_auth', '-v', _auth_dir + ':/auth',
                    'cesanta/docker_auth', '/auth/config.yml']
            subprocess.check_call(cmd2, stdout=DEVNULL)
        else:
            cmd += ['-e', 'REGISTRY_AUTH=htpasswd',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd']
    cmd += ['registry:2']
    subprocess.check_call(cmd, stdout=DEVNULL)
    return request.param

_fixture_params = [(None, False), (_auth, False), (_auth, True)]

@pytest.fixture(scope='module', params=_fixture_params)
def dtuf_objs(repo_dir, request):
    auth, do_token = _setup_fixture(request)
    class DTufObjs(object):
        def __init__(self):
            self.do_token = do_token
            self.repo_dir = repo_dir
            self.master = dtuf.DTufMaster('localhost:5000',
                                          pytest.repo,
                                          repo_dir,
                                          auth,
                                          not auth)
            self.copy = dtuf.DTufCopy('localhost:5000',
                                      pytest.repo,
                                      repo_dir,
                                      auth,
                                      not auth)
    r = DTufObjs()
    for _ in range(5):
        try:
            assert r.master.list_repos() == []
            return r
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex

@pytest.fixture(scope='module', params=_fixture_params)
def dtuf_main(repo_dir, request):
    auth, do_token = _setup_fixture(request)
    environ = {
        'DTUF_HOST': 'localhost:5000',
        'DTUF_REPOSITORIES_ROOT': repo_dir,
        'DTUF_INSECURE': '0' if auth else '1',
        'TEST_DO_TOKEN': do_token,
        'TEST_REPO_DIR': repo_dir
    }
    if auth:
        environ['DTUF_USERNAME'] = pytest.username
        environ['DTUF_PASSWORD'] = pytest.password
    for _ in range(5):
        try:
            assert dtuf.main.doit(['list-repos'], environ) == 0
            return environ
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex
