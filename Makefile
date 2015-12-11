export PYTHONPATH=.

all: lint test

docs: build_docs

.PHONY: build_docs
build_docs:
	cd docs && make html
	pandoc -t rst README.md | sed -e '1,1s/^[^\\]*//' -e '2d' > README.rst

.PHONY: lint
lint:
	pylint dtuf #test/*.py

