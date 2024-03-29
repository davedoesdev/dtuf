import os
try:
    os.remove('tuf.log')
    os.remove('dtuf.log')
except OSError as e:
    import errno
    if e.errno != errno.ENOENT:
        raise
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

DEVNULL = open(os.devnull, 'wb') # # pylint: disable=consider-using-with

def make_dummy_root_pub_key():
    import tuf.repository_tool
    import securesystemslib.keys
    return securesystemslib.keys.generate_rsa_key(tuf.repository_tool.DEFAULT_RSA_KEY_BITS)['keyval']['public']

def pytest_configure(config):
    setattr(pytest, 'blob1_file', os.path.join(_fixture_dir, 'blob1'))
    setattr(pytest, 'blob2_file', os.path.join(_fixture_dir, 'blob2'))
    setattr(pytest, 'blob3_file', os.path.join(_fixture_dir, 'blob3'))
    setattr(pytest, 'blob4_file', os.path.join(_fixture_dir, 'blob4'))

    setattr(pytest, 'blob1_hash', os.environ['HASH1'])
    setattr(pytest, 'blob2_hash', os.environ['HASH2'])
    setattr(pytest, 'blob3_hash', os.environ['HASH3'])
    setattr(pytest, 'blob4_hash', os.environ['HASH4'])

    setattr(pytest, 'blob1_size', 1 * 1024 * 1024)
    setattr(pytest, 'blob2_size', 2 * 1024 * 1024)
    setattr(pytest, 'blob3_size', 2 * 1024 * 1024)
    setattr(pytest, 'blob4_size', 2 * 1024 * 1024)

    setattr(pytest, 'username', 'fred')
    setattr(pytest, 'password', '!WordPass0$')

    setattr(pytest, 'repo', 'foo/bar')

    setattr(pytest, 'root_key_password', 'Dummypw1')
    setattr(pytest, 'targets_key_password', 'Dummypw2')
    setattr(pytest, 'snapshot_key_password', 'Dummypw3')
    setattr(pytest, 'timestamp_key_password', 'Dummypw4')

    setattr(pytest, 'make_dummy_root_pub_key', make_dummy_root_pub_key)

@pytest.fixture(scope='module')
def repo_dir(request):
    dir_name = tempfile.mkdtemp()
    def cleanup():
        # Be ultra cautious because we'll be doing rm -rf on this directory
        assert dir_name.startswith('/tmp/')
        shutil.rmtree(dir_name)
    request.addfinalizer(cleanup)
    return dir_name

def _auth(dtuf_obj, response):
    dtuf_obj.authenticate(pytest.username, pytest.password, response=response)

# pylint: disable=redefined-outer-name
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
    regver, auth, do_token = request.param
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
    cmd += ['registry:' + str(regver)]
    subprocess.check_call(cmd, stdout=DEVNULL)
    return auth, do_token

_fixture_params = []
for regver in [2, 2.2]:
    _fixture_params.extend([(regver, None, False),
                            (regver, _auth, False),
                            (regver, _auth, True)])

@pytest.fixture(scope='module', params=_fixture_params)
def dtuf_objs(repo_dir, request):
    auth, do_token = _setup_fixture(request)
    # pylint: disable=too-few-public-methods
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
    lex = Exception('should never be thrown')
    for _ in range(5):
        try:
            assert r.master.list_repos() == []
            return r
        except requests.exceptions.ConnectionError as ex:
            lex = ex
            time.sleep(1)
    raise lex

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
    lex = Exception('should never be thrown')
    for _ in range(5):
        try:
            assert dtuf.main.doit(['list-repos'], environ) == 0
            return environ
        except requests.exceptions.ConnectionError as ex:
            lex = ex
            time.sleep(1)
    raise lex
