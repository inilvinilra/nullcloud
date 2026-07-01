# Contributing to NullCloud

Thank you for your interest in contributing to NullCloud!

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

## Running Tests

```bash
pytest -v
```

## Code Style

- Keep changes focused and minimal.
- Add or update tests for new functionality.
- Ensure `python -m py_compile nullcloud.py reporting.py risk.py recon/*.py` succeeds.
- Avoid introducing hardcoded secrets or API keys.

## Reporting Issues

Please open a GitHub issue with a clear description, steps to reproduce and expected behavior.

## Pull Request Process

1. Create a feature branch.
2. Make your changes and add tests.
3. Ensure the CI checks pass.
4. Open a pull request with a descriptive title and summary.
