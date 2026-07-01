# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-02

### Added
- FOFA API integration via `recon/fofa.py`.
- `--origin-use-fofa` CLI flag to enable FOFA passive reconnaissance.
- `fofa` active reconnaissance module (`--origin-module fofa`).
- FOFA credentials in `keys.yaml.example`.
- Pytest test suite covering core helpers, risk scoring and FOFA module.
- GitHub Actions CI workflow for Python 3.10–3.13.
- `pyproject.toml` with packaging metadata and console script entry point.
- `CONTRIBUTING.md` and this `CHANGELOG.md`.

### Fixed
- Added missing `hashlib` and `base64` imports in `nullcloud.py`; favicon hashing now works.
- Corrected `--origin-module` help text to match the actual default (`asn, cloud, body`).
- Corrected `--origin-sample` help text to describe prefix sampling accurately.

### Changed
- README updated with FOFA usage, Thanks section, development instructions and corrected option descriptions.
