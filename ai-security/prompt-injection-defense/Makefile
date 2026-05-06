.PHONY: test demo lint install clean

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ -v --cov=src --cov-report=term-missing

demo:
	python examples/basic_usage.py

scan:
	python -m src.cli scan "$(INPUT)"

install:
	pip install pytest pytest-cov

lint:
	python -m py_compile src/detector.py src/patterns.py src/sanitizer.py src/logger.py src/cli.py
	@echo "Syntax OK"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

help:
	@echo "make test      — run full test suite"
	@echo "make test-cov  — run tests with coverage report"
	@echo "make demo      — run basic usage demo"
	@echo "make scan INPUT='your text here'  — scan a single string"
	@echo "make install   — install dev dependencies"
	@echo "make lint      — syntax check all source files"
	@echo "make clean     — remove __pycache__ and .pyc files"
