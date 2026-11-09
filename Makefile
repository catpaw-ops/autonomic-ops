PYTHON ?= python3
export PYTHONPATH := $(CURDIR)/src$(if $(PYTHONPATH),:$(PYTHONPATH),)

.PHONY: help check test test-no-yaml selftest doctor clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

check:  ## Syntax, shell and config sanity checks (works on any OS)
	$(PYTHON) -m compileall -q src
	@bash -n scripts/*.sh tests/*.sh
	@$(PYTHON) -c "import sys; sys.path.insert(0, 'src'); import autonomic; print('package:', autonomic.version_string())"

test:  ## Run the unit tests
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

test-no-yaml:  ## Run unit tests with PyYAML unavailable (zero-dependency path)
	@$(PYTHON) -c "import sys, unittest; sys.modules['yaml'] = None; \
suite = unittest.defaultTestLoader.discover('tests', pattern='test_*.py'); \
sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)"

selftest:  ## Full end-to-end self-test (LINUX ONLY; uses /tmp, never production paths)
	bash tests/selftest.sh

doctor:  ## Environment / config self-check using the portable selftest config
	$(PYTHON) -m autonomic.main -c config/config.selftest.yaml --doctor

clean:  ## Remove local bytecode caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
