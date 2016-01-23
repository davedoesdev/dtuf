#!/usr/bin/env python

# Requires DOCKER_HUB_USERNAME, DOCKER_HUB_PASSWORD and DOCKER_HUB_REPO env vars
# $DOCKER_HUB_REPO should have been created on Docker Hub

# pylint: disable=wrong-import-position,superfluous-parens
# pylint: disable=redefined-outer-name,redefined-variable-type
import os
from os import path
import sys
import shutil
import errno

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))
try:
    shutil.rmtree('/tmp/dtuf_repos')
except OSError as ex:
    if ex.errno != errno.ENOENT:
        raise
os.chdir('/tmp')


from dtuf import DTufMaster

def auth(dtuf, response):
    dtuf.authenticate(os.environ['DOCKER_HUB_USERNAME'],
                      os.environ['DOCKER_HUB_PASSWORD'],
                      response=response)

dtuf = DTufMaster('registry-1.docker.io',
                  os.environ['DOCKER_HUB_REPO'],
                  auth=auth)

with open('demo.txt', 'w') as f:
    f.write('Hello World!\n')

dtuf.create_root_key('demo')
dtuf.create_metadata_keys('demo', 'demo', 'demo')
dtuf.create_metadata('demo', 'demo', 'demo', 'demo')
dtuf.push_target('demo.txt', 'demo.txt')
dtuf.push_metadata('demo', 'demo', 'demo')


from dtuf import DTufCopy

dtuf = DTufCopy('registry-1.docker.io',
                os.environ['DOCKER_HUB_REPO'],
                auth=auth)

with open('dtuf_repos/' + \
          os.environ['DOCKER_HUB_REPO'] + \
          '/master/keys/root_key.pub') as f:
    assert dtuf.pull_metadata(f.read()) == ['demo.txt']

s = ''
for download in dtuf.pull_target('demo.txt'):
    for chunk in download:
        s += chunk
assert s == 'Hello World!\n'
print(s)
