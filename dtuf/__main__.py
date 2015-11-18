# dtuf auth <repo> <action>...         auth with DTUF_USERNAME/DTUF_PASSWORD
#                                      and print token

# dtuf create-root-key <repo>          create root key for repo
# dtuf create-metadata-keys <repo>     create metadata keys for repo
# dtuf create-metadata <repo>          create metadata for repo

# dtuf push-blob <repo> <file> @alias  upload blob from file and set alias to it
# dtuf push-blob <repo> @alias @alias2 set alias to blob already uploaded
# dtuf del-blob <repo> @alias...       delete blobs
# dtuf push-metadata <repo>            update metadata and push it to remote

# dtuf pull-metadata <repo> [<root-pubkey-file>]
#                                      pull metadata from remote and print
#                                      updated aliases
# dtuf pull-blob <repo> @alias...      download blobs to stdout
# dtuf list-aliases <repo>             list all aliases in a repo

# pass private key password through DTUF_ROOT_KEY_PASSWORD,
# DTUF_TARGETS_KEY_PASSWORD, DTUF_SNAPSHOT_KEY_PASSWORD and
# DTUF_TIMESTAMP_KEY_PASSWORD

# pass repo host through DTUF_HOST
# to use http, set DTUF_INSECURE to something
# pass token through DTUF_TOKEN

# pass repositories directory through DTUF_REPOSITORIES_ROOT
# (have repo subdirs underneath and then master and copy subdirs under those)

import os
import sys
import argparse
import dtuf
import dtuf.exceptions

parser = argparse.ArgumentParser()
parser.add_argument('op', choices=['auth',
                                   'create-root-key',
                                   'create-metadata-keys',
                                   'create-metadata',
                                   'push-blob',
                                   'del-blob',
                                   'push-metadata',
                                   'pull-metadata',
                                   'pull-blob',
                                   'list-aliases'])
parser.add_argument('repo')
parser.add_argument('args', nargs='*')
args = parser.parse_args()

def auth(dtuf_obj, response):
    username = os.environ.get('DTUF_USERNAME')
    password = os.environ.get('DTUF_PASSWORD')
    if username and password:
        dtuf_obj.auth_by_password(username, password, response=response)

dtuf_obj = dtuf.DTuf(os.environ['DTUF_HOST'],
                     args.repo,
                     os.environ.get('DTUF_REPOSITORIES_ROOT'),
                     auth,
                     os.environ.get('DTUF_INSECURE'))

def doit():
    if args.op == 'auth':
        print dtuf_obj.auth_by_password(os.environ['DTUF_USERNAME'],
                                        os.environ['DTUF_PASSWORD'],
                                        actions=args.args)
        return

    token = os.environ.get('DTUF_TOKEN')
    if token:
        dtuf_obj.token = token

    if args.op == 'create-root-key':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_obj.create_root_key(os.environ.get('DTUF_ROOT_KEY_PASSWORD'))

    elif args.op == 'create-metadata-keys':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_obj.create_metadata_keys(os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                      os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                      os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

    elif args.op == 'create-metadata':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_obj.create_metadata(os.environ.get('DTUF_ROOT_KEY_PASSWORD'),
                                 os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                                 os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                                 os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

    elif args.op == 'push-blob':
        if len(args.args) < 2:
            parser.error('too few arguments')
        if len(args.args) > 2:
            parser.error('too many arguments')
        if not args.args[1].startswith('@'):
            parser.error('invalid alias')
        dtuf_obj.push_blob(args.args[0], args.args[1][1:])

    elif args.op == 'del-blob':
        for name in args.args:
            if not name.startswith('@'):
                parser.error('invalid alias')
            dtuf_obj.del_blob(name[1:])

    elif args.op == 'push-metadata':
        if len(args.args) > 0:
            parser.error('too many arguments')
        dtuf_obj.push_metadata(os.environ.get('DTUF_TARGETS_KEY_PASSWORD'),
                               os.environ.get('DTUF_SNAPSHOT_KEY_PASSWORD'),
                               os.environ.get('DTUF_TIMESTAMP_KEY_PASSWORD'))

    elif args.op == 'pull-metadata':
        if len(args.args) > 1:
            parser.error('too many arguments')
        root_public_key = None
        if len(args.args) == 1:
            with open(args.args[0], 'rb') as f:
                root_public_key = f.read()
        for name in dtuf_obj.pull_metadata(root_public_key):
            print name

    elif args.op == 'pull-blob':
        for name in args.args:
            if not name.startswith('@'):
                parser.error('invalid alias')
            for chunk in dtuf_obj.pull_blob(name[1:]):
                sys.stdout.write(chunk)

    elif args.op == 'list-aliases':
        if len(args.args) > 0:
            parser.error('too many arguments')
        for name in dtuf_obj.list_aliases():
            print name

try:
    doit()
except dtuf.exceptions.DXFUnauthorizedError:
    import traceback
    traceback.print_exc()
    import errno
    exit(errno.EACCES)
