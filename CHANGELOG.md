# Changelog

All notable changes to LedgerProbe are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

Version numbers are maintained in `pkg/version.py` and bumped when the
maintainer chooses; no Git tags are required.

## [Unreleased]

### Changed

- Installation documentation now uses pipx or a local virtual environment from
  GitHub, with Docker built locally from a clone.
- The runtime JSON schemas are installed as package data so the CLI works
  outside the repository.

## [1.1.0] - 2026-11-07

### Added

- Differential authorization checks with owner baselines, forbidden identities,
  canaries, nonexistent and unauthenticated controls, confirmations, and
  three-state verdicts.
- State-changing mutation checks with `verify:` and mandatory `restore:`.
- Race checks with burst and HTTP/1.1 last-byte synchronization, bounded rounds,
  weak-synchronization detection, and a fixture study in `docs/RACE.md`.
- BFLA fixtures and access-matrix expansion; experimental mass-assignment and
  business-limit checks behind `--experimental`.
- SARIF 2.1.0, JUnit, versioned JSON results, DefectDojo export, Jira/Linear
  ticket lifecycle, Slack digest, baselines, and suppressions.
- Docker image, composite GitHub Action, JSON logs, Prometheus metrics, kill
  switch, environment gating, and scan identification headers.
- Benchmark harness and frozen VAmPI/crAPI results, including the object-scoped
  cut and reduced-confidence marker.
- N=50 wallet race fixture study with Wilson 95% intervals.
- LedgerProbe dashboard benchmark page, verdict legend, and sample-data banner.

### Changed

- README now leads with counts-based benchmark results and states check-type
  maturity honestly.
- Repository identity is LedgerProbe; `mock-bank-api` is documented as a test
  fixture.
- Docker image license label now matches the repository's MIT license.

### Fixed

- Historical fake-token fixtures no longer trigger the secret scanner; exact
  historical fingerprints are documented in `.gitleaksignore`.
- Gitleaks is pinned and checksum-verified; Trivy image findings are resolved by
  the refreshed base digest and apt-only upgrade.
- CI test jobs install the package's `dev` extra.
