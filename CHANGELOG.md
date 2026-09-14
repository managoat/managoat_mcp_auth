# Changelog

All notable changes to `managoat_mcp_auth` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Pre-1.0, a minor bump (`0.x` to `0.y`) may
include breaking changes and says so; patch releases are always safe to take.

Merging a version bump to `main` publishes it to hex; a PR that changes what
the package ships without a bump fails the release gate.

## [Unreleased]

## [0.2.0] - 2026-09-14

### Added

- `Managoat.McpAuth.Client`, the OAuth 2.0 authorization-code client that
  completes the client side of MCP authorization: the authorize URL (PKCE
  S256, the RFC 8707 `resource`, provider-specific `authorize_params`), the
  code exchange, the refresh and the RFC 7009 revoke, driven by a
  `Managoat.McpAuth.Client.Config` struct. Client authentication is
  `client_secret_post`, `client_secret_basic` or `none`; a provider that
  nests its grant (Slack's `authed_user`) names the key in `token_body_nest`
  and the client lifts it to the RFC 6749 top level; an error carried in a
  200 body is an error; `invalid_grant` and its GitHub and Slack spellings
  come back as `{:error, :invalid_grant}`; the account label is read from
  `userinfo_url` along a dotted `account_label_path`. Every URL passes
  `Managoat.McpAuth.UrlGuard` at the moment it is fetched unless the config
  marks them `trusted_urls?`. Ported from Fountain's `Fountain.Connections.OAuth`
  (managoat/fountain#2152).

## [0.1.1] - 2026-09-03

### Changed

- Expanded coverage of discovery fallbacks, malformed and failed provider
  responses, registration negotiation, and every private-address class in the
  URL guard, and raised the coverage gate from 70% to 100%.

## [0.1.0] - 2026-09-02

### Added

- Extracted from Fountain (BinaryBourbon/fountain#1350).
