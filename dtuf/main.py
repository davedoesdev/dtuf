# dtuf auth <repo> <action>...         auth with DTUF_USERNAME/DTUF_PASSWORD
#                                      and print token

# dtuf create-root-key <repo>          create root key for repo
# dtuf create-metadata-keys <repo>     create metadata keys for repo
# dtuf create-metadata <repo>          create metadata for repo
# dtuf reset-keys <repo>               reset repo keys

# dtuf push-target <repo> @target <@target|file>...
#                                      make a new target by uploading blobs
#                                      from files or using blobs from existing
#                                      targets
# dtuf del-target <repo> @target...    delete blobs and targets pointing to them
# dtuf push-metadata <repo>            update metadata and push it to remote
# dtuf list-master-targets <repo>      list all targets in a repo

# dtuf pull-metadata <repo> [<root-pubkey-file>|-]
#                                      pull metadata from remote and print
#                                      updated targets
# dtuf pull-target <repo> @target...   download blobs to stdout
# dtuf blob-sizes <repo> @target...    print sizes of blobs
# dtuf check-target <repo> @target <file>...
#                                      check files are latest blobs for target
# dtuf list-copy-targets <repo>        list all targets in a repo
# dtuf list-repos                      list all repos (may not all be TUF)

# pass private key password through DTUF_ROOT_KEY_PASSWORD,
# DTUF_TARGETS_KEY_PASSWORD, DTUF_SNAPSHOT_KEY_PASSWORD and
# DTUF_TIMESTAMP_KEY_PASSWORD

# pass repo host through DTUF_HOST
# to use http, set DTUF_INSECURE to something
# pass token through DTUF_TOKEN

# pass repositories directory through DTUF_REPOSITORIES_ROOT
# (have repo subdirs underneath and then master and copy subdirs under those)

# DTUF_PROGRESS for progress bar on push-target, push-metadata, pull-metadata
# and pull-target

# DTUF_BLOB_INFO to prepend digest and size before blob for pull-target

# pylint: disable=wrong-import-position,wrong-import-order,superfluous-parens
import os
import sys
import argparse
import tqdm
import tuf
import dtuf
import dxf.exceptions

choices = ['list-repos',
           'auth',
           'create-root-key',
           'create-metadata-keys',
           'create-metadata',
           'reset-keys',
           'push-target',
           'del-target',
           'push-metadata',
           'list-master-targets',
           'pull-metadata',
           'pull-target',
           'blob-sizes',
           'check-target',
           'list-copy-targets']

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='op')
for c in choices:
    sp = subparsers.add_parser(c)
    if c != 'list-repos':
        sp.add_argument('repo')
        sp.add_argument('args', nargs='*')

def access_denied():
    import traceback
    traceback.print_exc()
    import errno
    return errno.EACCES

# pylint: disable=too-many-statements
def doit(args, environ):
    if environ.get('DTUF_PROGRESS') == '1':
        bars = {}
        def progress(dgst, chunk, size):
            if dgst not in bars:
                bars[dgst] = tqdm.tqdm(desc=dgst[0:8],
                                       total=size,
                                       leave=True)
            if len(chunk) > 0:
                bars[dgst].update(len(chunk))
            if bars[dgst].n >= bars[dgst].total:
                bars[dgst].close()
                del bars[dgst]
    else:
        progress = None

    def auth(dtuf_obj, response):
        # pylint: disable=redefined-outer-name
        username = environ.get('DTUF_USERNAME')
        password = environ.get('DTUF_PASSWORD')
        if username and password:
            dtuf_obj.auth_by_password(username, password, response=response)

    # pylint: disable=redefined-variable-type
    args = parser.parse_args(args)
    if args.op == 'list-repos':
        dtuf_base = dtuf.DTufBase(environ['DTUF_HOST'],
                                  auth,
                                  environ.get('DTUF_INSECURE') == '1')
        dtuf_obj = dtuf_base
    elif args.op in ['auth',
                     'create-root-key',
                     'create-metadata-keys',
                     'create-metadata',
                     'reset-keys',
                     'push-target',
                     'del-target',
                     'push-metadata',
                     'list-master-targets']:
        dtuf_master = dtuf.DTufMaster(environ['DTUF_HOST'],
                                      args.repo,
                                      environ.get('DTUF_REPOSITORIES_ROOT'),
                                      auth,
                                      environ.get('DTUF_INSECURE') == '1')
        dtuf_obj = dtuf_master
    else:
        dtuf_copy = dtuf.DTufCopy(environ['DTUF_HOST'],
                                  args.repo,
                                  environ.get('DTUF_REPOSITORIES_ROOT'),
                                  auth,
                                  environ.get('DTUF_INSECURE') == '1')
        dtuf_obj = dtuf_copy

    def _doit():
        # pylint: disable=too-many-branches,too-many-statements
        if args.op == 'auth':
            token = dtuf_master.auth_by_password(environ['DTUF_USERNAME'],
                                                 environ['DTUF_PASSWORD'],
                                                 actions=args.args)
            if token:
                print(token)
            return

        token = environ.get('DTUF_TOKEN')
        if token:
            dtuf_obj.token = token

        if args.op == 'create-root-key':
            if len(args.args) > 0:
                parser.error('too many arguments')
            dtuf_master.create_root_key(environ.get('DTUF_ROOT_KEY_PASSWORD'))

        elif args.op == 'create-metadata-keys':
            if len(args.args) > 0:
                parser.error('too many arguments')
            dtuf_master.create_metadata_keys(environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                             environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                             environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

        elif args.op == 'create-metadata':
            if len(args.args) > 0:
                parser.error('too many arguments')
            dtuf_master.create_metadata(environ.get('DTUF_ROOT_KEY_PASSWORD'),
                                        environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                        environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                        environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

        elif args.op == 'reset-keys':
            if len(args.args) > 0:
                parser.error('too many arguments')
            dtuf_master.reset_keys(environ.get('DTUF_ROOT_KEY_PASSWORD'),
                                   environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                   environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                   environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

        elif args.op == 'push-target':
            if len(args.args) < 2:
                parser.error('too few arguments')
            dtuf_master.push_target(args.args[0],
                                    *args.args[1:],
                                    progress=progress)

        elif args.op == 'del-target':
            for name in args.args:
                dtuf_master.del_target(name)

        elif args.op == 'push-metadata':
            if len(args.args) > 0:
                parser.error('too many arguments')
            dtuf_master.push_metadata(environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                      environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                      environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'),
                                      progress)

        elif args.op == 'list-master-targets':
            if len(args.args) > 0:
                parser.error('too many arguments')
            for name in dtuf_master.list_targets():
                print(name)

        elif args.op == 'pull-metadata':
            if len(args.args) > 1:
                parser.error('too many arguments')
            root_public_key = None
            if len(args.args) == 1:
                if args.args[0] == '-':
                    root_public_key = sys.stdin.read()
                else:
                    with open(args.args[0], 'rb') as f:
                        root_public_key = f.read()
            for name in dtuf_copy.pull_metadata(root_public_key, progress):
                print(name)

        elif args.op == 'pull-target':
            for name in args.args:
                for it, dgst, size in dtuf_copy.pull_target(name, True):
                    if environ.get('DTUF_BLOB_INFO') == '1':
                        print(dgst + ' ' + str(size))
                    dtuf.write_with_progress(it, dgst, size, sys.stdout, progress)

        elif args.op == 'blob-sizes':
            for name in args.args:
                for size in dtuf_copy.blob_sizes(name):
                    print(size)

        elif args.op == 'check-target':
            if len(args.args) < 2:
                parser.error('too few arguments')
            dtuf_copy.check_target(args.args[0], *args.args[1:])

        elif args.op == 'list-copy-targets':
            if len(args.args) > 0:
                parser.error('too many arguments')
            for name in dtuf_copy.list_targets():
                print(name)

        elif args.op == 'list-repos':
            for name in dtuf_base.list_repos():
                print(name)

    try:
        _doit()
        return 0
    except dxf.exceptions.DXFUnauthorizedError:
        return access_denied()
    except tuf.NoWorkingMirrorError as ex:
        for ex2 in ex.mirror_errors.values():
            if isinstance(ex2, dxf.exceptions.DXFUnauthorizedError):
                return access_denied()
        raise

def main():
    exit(doit(sys.argv[1:], os.environ))
