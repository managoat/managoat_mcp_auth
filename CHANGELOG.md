# Changelog

All notable changes to `managoat_mcp_auth` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Pre-1.0, a minor bump (`0.x` to `0.y`) may
include breaking changes and says so; patch releases are always safe to take.

Merging a version bump to `main` publishes it to hex; a PR that changes what
the package ships without a bump fails the release gate.

## [Unreleased]

## [0.1.1] - 2026-09-03

### Changed

- Expanded coverage of discovery fallbacks, malformed and failed provider
  responses, registration negotiation, and every private-address class in the
  URL guard, and raised the coverage gate from 70% to 100%.

## [0.1.0] - 2026-09-02

### Added

- Extracted from Fountain (BinaryBourbon/fountain#1350).
