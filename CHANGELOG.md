# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-02

### Fixed

- The docs claimed OmniAuth's test mode skips the identity checks. It doesn't: test mode skips the
  trip to vits.me, but `expected_uid` and `require_verified` still judge the mocked answer. The
  README, the test helper and the skill now say so, and four specs pin the behaviour. The examples
  mock someone else to get `:identity_mismatch` and keep `mock_failure` for refusals only vits.me
  makes.

## [0.2.0] - 2026-11-02

A rewrite that brings the gem up to the vits.me platform. **Breaking:** the auth hash changed shape,
and Ruby ≥ 3.3 is required.

### Added

- `expected_uid:` for follow-up questions about a person already signed in. vits.me is told whom to
  expect (OIDC `claims` sub value) and pre-selects that person. The callback refuses anyone else
  (`:identity_mismatch`) and fails early when nobody is signed in (`:not_signed_in`). Earlier SOLIDs
  listed in `defunct_solids` still match.
- `require_verified:` refuses pending (`fluid_`) identities (`:unverified_identity`). It is on by
  default with `expected_uid`.
- `nationality_gate: %w[IL]` adds `openid_nationality__xx` gate scopes. A gate refusal is
  `:nationality_gate_refused`, read from vits.me's machine-readable `vitsme_error`. Combining a gate
  with `fluid` raises at boot.
- `environment:` (`:production` / `:staging` / `:development`) and `OmniAuth::Vitsme.issuer`. The host
  is derived from the issuer.
- `data/claims.json`: a machine-readable catalog of every scope, claim, type, gate and refusal.
  `scope:` is validated against it at boot.
- `extra.claims`: the shared claims, typed (booleans, integers). `extra.identity` (`:solid` / `:fluid`),
  `extra.lookup_uids` (current + defunct) and `extra.fluid_uids`. `info.verified`.
- PKCE (S256) and `prompt: :login` by default. `redirect_uri` defaults to the provider's callback.
- `OmniAuth::Vitsme::Test` (`mock_auth`, `mock_failure`), which builds mocks with the real shape.
- `bin/rails g omniauth_vitsme:install`: initializer, callbacks controller, en/he messages, sign-in
  button, routes and a `vitsme_uid` migration.
- `examples/rails/app.rb`, booted by the test suite. AGENTS.md, llms.txt and a Claude Code skill
  (`.claude/skills/vitsme-integrate`).

### Changed

- `info` holds only what vits.me sends: `name`, `nationality`, `verified`. `credentials` holds
  `id_token` and `scope` (vits.me issues no refresh token and its access token lapses in 5 s).

### Removed

- `info.first_name`, `last_name`, `email`, `birthday`, `age_over_*`: vits.me never sent the first
  three. `birthday` conflated `birthdate` with a month-day value. The `age_over_*` flags passed
  `"false"` through as a truthy string. Use `extra.claims`.
- Ruby 3.0–3.2 support.

## [0.1.0] - 2026-02-11

### Added

- Initial release
- OmniAuth strategy for vits.me OpenID Connect provider
- OIDC discovery enabled by default
- RS256 token signing
- Support for vits.me scopes: openid, name, nationality, age verification, birthday
- Convenience `client_id` / `client_secret` top-level options
