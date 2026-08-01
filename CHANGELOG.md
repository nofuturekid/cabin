# Changelog

All notable changes to cabin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor = feature, patch = fix).

## [Unreleased]

### Added

- Spec 0001 (foundation): project skeleton, config (flag > env > default),
  SQLite via SQLAlchemy + Alembic with migrations applied at startup,
  `/healthz` endpoint, `cabin` CLI entry point, CI (ruff, mypy, pytest).
