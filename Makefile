.PHONY: check format frontend test verify

PYTHON := .venv/bin/python

check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m black --check .
	$(PYTHON) -m mypy .

format:
	$(PYTHON) -m ruff check . --fix
	$(PYTHON) -m black .

test:
	PYTHONPATH=.. DEBUG=true $(PYTHON) -m pytest

frontend:
	npx --yes prettier@3.6.2 --check \
		.github/workflows/ci.yml .github/workflows/dependency-audit.yml \
		scripts/browser_acceptance.cjs \
		static/index.js static/index.css static/routes.json \
		templates/externalsigner/index.html config.json manifest.json

verify: check test frontend
