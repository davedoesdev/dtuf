#!/bin/bash
set -e
HERE="$(cd $(dirname "$0"); echo "$PWD")"
cd /tmp
rm -rf dtuf_repos

dtuf() {
  PYTHONPATH="$HERE/.." python -m dtuf "$@"
}

cleanup() {
    trap - EXIT
    "$HERE/remove_container.sh" dtuf_registry
}
trap cleanup EXIT
docker run -d -p 5000:5000 --name dtuf_registry registry:2

export DTUF_HOST=localhost:5000
export DTUF_INSECURE=1
export DTUF_ROOT_KEY_PASSWORD=dummy
export DTUF_TARGETS_KEY_PASSWORD=dummy
export DTUF_SNAPSHOT_KEY_PASSWORD=dummy
export DTUF_TIMESTAMP_KEY_PASSWORD=dummy

echo 'Hello World!' > demo.txt
dtuf create-root-key fred/demo
dtuf create-metadata-keys fred/demo
dtuf create-metadata fred/demo
dtuf push-target fred/demo demo.txt demo.txt
dtuf push-metadata fred/demo

dtuf pull-metadata fred/demo dtuf_repos/fred/demo/master/keys/root_key.pub
dtuf pull-target fred/demo demo.txt

echo 'Update World!' > demo.txt
echo 'Another World!' > demo2.txt
dtuf push-target fred/demo demo.txt demo.txt
dtuf push-target fred/demo demo2.txt demo2.txt
dtuf push-metadata fred/demo

dtuf pull-metadata fred/demo
dtuf pull-target fred/demo demo.txt
dtuf pull-target fred/demo demo2.txt
