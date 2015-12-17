# dtuf auth <repo> <action>...         auth with DTUF_USERNAME/DTUF_PASSWORD
#                                      and print token

# dtuf create-root-key <repo>          create root key for repo
# dtuf create-metadata-keys <repo>     create metadata keys for repo
# dtuf create-metadata <repo>          create metadata for repo

# dtuf push-blobs <repo> @alias <@alias|file>...  upload blobs from files or blobs already uploads and set alias to them
# dtuf del-blobs <repo> @alias...      delete blobs and aliases pointing to them
# dtuf push-metadata <repo>            update metadata and push it to remote
# dtuf list-master-aliases <repo>      list all aliases in a repo

# dtuf pull-metadata <repo> [<root-pubkey-file>]
#                                      pull metadata from remote and print
#                                      updated aliases
# dtuf pull-blobs <repo> @alias...     download blobs to stdout
# dtuf blob-sizes <repo> @alias...     print sizes of blobs
# dtuf check-blobs <repo> @alias <file>... check files are latest blobs for alias
# dtuf list-copy-aliases <repo>        list all aliases in a repo
# dtuf list-repos                      list all repos (may not all be TUF)

# pass private key password through DTUF_ROOT_KEY_PASSWORD,
# DTUF_TARGETS_KEY_PASSWORD, DTUF_SNAPSHOT_KEY_PASSWORD and
# DTUF_TIMESTAMP_KEY_PASSWORD

# pass repo host through DTUF_HOST
# to use http, set DTUF_INSECURE to something
# pass token through DTUF_TOKEN

# pass repositories directory through DTUF_REPOSITORIES_ROOT
# (have repo subdirs underneath and then master and copy subdirs under those)

# pylint: disable=wrong-import-position,wrong-import-order,superfluous-parens
import os
import sys
import argparse
import tqdm
import dtuf
import dxf.exceptions

# pylint: disable=redefined-outer-name
def auth(dtuf_obj, response):
    username = os.environ.get('DTUF_USERNAME')
    password = os.environ.get('DTUF_PASSWORD')
    if username and password:
        dtuf_obj.auth_by_password(username, password, response=response)

choices = ['list-repos',
           'auth',
           'create-root-key',
           'create-metadata-keys',
           'create-metadata',
           'push-blobs',
           'del-blobs',
           'push-metadata',
           'list-master-aliases',
           'pull-metadata',
           'pull-blobs',
           'blob-sizes',
           'check-blobs',
           'list-copy-aliases']

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='op')
for c in choices:
    sp = subparsers.add_parser(c)
    if c != 'list-repos':
        sp.add_argument('repo')
        sp.add_argument('args', nargs='*')

if os.environ.get('DTUF_PROGRESS') == '1':
    bars = {}
    def _progress(dgst, chunk, size):
        if len(chunk) > 0:
            if dgst not in bars:
                bars[dgst] = tqdm.tqdm(desc=dgst[0:8],
                                       total=size,
                                       leave=True)
            bars[dgst].update(len(chunk))
        elif dgst in bars:
            bars[dgst].close()
else:
    _progress = None

# pylint: disable=redefined-variable-type
args = parser.parse_args()
if args.op == 'list-repos':
    dtuf_base = dtuf.DTufBase(os.environ['DTUF_HOST'],
                              auth,
                              os.environ.get('DTUF_INSECURE'))
    dtuf_obj = dtuf_base
elif args.op in ['auth',
                 'create-root-key',
                 'create-metadata-keys',
                 'create-metadata',
                 'push-blob',
                 'del-blob',
                 'push-metadata',
                 'list-master-aliases']:
    dtuf_master = dtuf.DTufMaster(os.environ['DTUF_HOST'],
                                  args.repo,
                                  os.environ.get('DTUF_REPOSITORIES_ROOT'),
                                  auth,
                                  os.environ.get('DTUF_INSECURE'))
    dtuf_obj = dtuf_master
else:
    dtuf_copy = dtuf.DTufCopy(os.environ['DTUF_HOST'],
                              args.repo,
                              os.environ.get('DTUF_REPOSITORIES_ROOT'),
                              auth,
                              os.environ.get('DTUF_INSECURE'))
    dtuf_obj = dtuf_copy

# pylint: disable=too-many-branches,too-many-statements
def doit():
    if args.op == 'auth':
        print(dtuf_master.auth_by_password(os.environ['DTUF_USERNAME'],
                                           os.environ['DTUF_PASSWORD'],
                                           actions=args.args))
        return

    token = os.environ.get('DTUF_TOKEN')
    if token:
        dtuf_obj.token = token

    if args.op == 'create-root-key':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_master.create_root_key(os.environ.get('DTUF_ROOT_KEY_PASSWORD'))

    elif args.op == 'create-metadata-keys':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_master.create_metadata_keys(os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                         os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                         os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

    elif args.op == 'create-metadata':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_master.create_metadata(os.environ.get('DTUF_ROOT_KEY_PASSWORD'),
                                    os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                    os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                    os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

    elif args.op == 'push-blobs':
        if len(args.args) < 2:
            parser.error('too few arguments')
        if not args.args[0].startswith('@'):
            parser.error('invalid alias')
        dtuf_master.push_blobs(args.args[0][1:],
                               *args.args[1:],
                               progress=_progress)

    elif args.op == 'del-blobs':
        for name in args.args:
            if not name.startswith('@'):
                parser.error('invalid alias')
            dtuf_master.del_blobs(name[1:])

    elif args.op == 'push-metadata':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_master.push_metadata(os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                  os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                  os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'),
                                  _progress)

    elif args.op == 'list-master-aliases':
        if len(args.args) > 0:
            parser.error('too many arguments')
        for name in dtuf_master.list_aliases():
            print(name)

    elif args.op == 'pull-metadata':
        if len(args.args) > 1:
            parser.error('too many arguments')
        root_public_key = None
        if len(args.args) == 1:
            with open(args.args[0], 'rb') as f:
                root_public_key = f.read()
        for name in dtuf_copy.pull_metadata(root_public_key, _progress):
            print(name)

    elif args.op == 'pull-blobs':
        for name in args.args:
            if not name.startswith('@'):
                parser.error('invalid alias')
            for it, dgst, size in dtuf_copy.pull_blobs(name[1:], True):
                # pylint: disable=blacklisted-name
                if os.environ.get('DTUF_PROGRESS') == '1':
                    bar = tqdm.tqdm(desc=dgst[0:8], total=size, leave=True)
                else:
                    bar = None
                for chunk in it:
                    if bar is not None:
                        bar.update(len(chunk))
                    sys.stdout.write(chunk)
                if bar is not None:
                    bar.close()

    elif args.op == 'blob-sizes':
        for name in args.args:
            if not name.startswith('@'):
                parser.error('invalid alias')
            for size in dtuf_copy.blob_sizes(name[1:]):
                print(size)

    elif args.op == 'check-blobs':
        if len(args.args) < 2:
            parser.error('too few arguments')
        if not args.args[0].startswith('@'):
            parser.error('invalid alias')
        dtuf_copy.check_blobs(args.args[0][1:], *args.args[1:])

    elif args.op == 'list-copy-aliases':
        if len(args.args) > 0:
            parser.error('too many arguments')
        for name in dtuf_copy.list_aliases():
            print(name)

    elif args.op == 'list-repos':
        for name in dtuf_base.list_repos():
            print(name)

try:
    doit()
except dxf.exceptions.DXFUnauthorizedError:
    import traceback
    traceback.print_exc()
    import errno
    exit(errno.EACCES)
