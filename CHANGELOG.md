# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1] - 2026-11-28

### Changed

- The catalog describes `full_name__local` as the name in the person's own language and script, and no longer as
  the name their documents print: that would be another scope. Words only.

## [0.8.0] - 2026-11-28

Required scopes.

### Added

- A star after a scope marks it required in an ask: `scope: %i[full_name__intl*]` for vits.me,
  `scope: %w[email*]` for `provider :vitsme_partner` and a trip's stops. The consent page marks it and waits until
  the person gives it; the person may still cancel. The star goes to the server as written, and everything else
  (the catalog check at boot, `label_hint`, the claims) reads the plain name.
- `:required_missing`, when an answer comes back without a required claim; on a trip, that stop's `error`. The
  install generator's failure messages include it.

### Changed

- A star on `openid`, `fluid`, a gate or on nothing raises `ArgumentError` at boot.

## [0.7.0] - 2026-11-27

vits.me now tells a sign-in from an ask by whether the request names the person it is about, and refuses a
request for details that names nobody. It can also ask vits.me and partners under one pincode.

### Changed (breaking)

- `expected_uid:` is now `ask_about:`. It returns the vits.me ID token you kept for the signed-in person
  (`auth.credentials.id_token`), or the uid you store; the gem sends the token's `sub` (or the uid) as the
  `claims` sub value, as before. `send_expected_uid:` is gone: vits.me is always told. Either old name raises
  `ArgumentError` at boot, naming the new one.
- A `provider :vitsme` asking for a claim scope without `ask_about:` raises at boot: a sign-in asks only
  `openid` and gates. Ask for details from a button once the person is signed in.
- Every ask is pushed to vits.me first (RFC 9126, `pushed_authorization_request_endpoint`), so the browser
  carries only `client_id` and a `request_uri`. Sign-ins are unchanged.
- `provider :vitsme_partner`'s `id_token:` is now `ask_about:`, and `Partner.hint` is
  `Partner.seal_subject`.
- The install generator has no `--scope` any more: a sign-in asks no details. `--verify` writes an ask.

### Added

- `provider :vitsme_trip`: vits.me and then each partner in `stops:` from one button, under one pincode. The
  first ask is pushed with `vitsme_stops`; each partner is asked with the fresh ID token, which carries the
  trip's ticket, sealed; each code is redeemed on arrival and the answers wait in `store:`, never the session.
  One auth hash at the end, with `extra.stops`. `OmniAuth::Vitsme::Test.mock_trip`.
- `Partner.ask`, which both partner strategies use; `OmniAuth::Vitsme::Subject`.
- `label_hint`: which label your site would like for an item under a scope, pushed to the partner as
  space-separated `scope:label` pairs (`label_hint=email:work phone:mobile`), only for scopes the request asks.
  A Hash `{ scope => label }` on a trip's stop (kept with the stop in `store:`, sent with that stop's request
  only), as `Partner.ask(label_hint:)`, and as `provider :vitsme_partner`'s `label_hint` option (a Hash, or
  `->(env) { {...} }`). The partner may use it to sort the person's items and never tells it back. Only the
  shape is checked: a malformed static hint raises `ArgumentError` at boot, and a malformed pair worked out at
  the click is dropped. `OmniAuth::Vitsme::LabelHint`.
- Failure types `:subject_required`, `:subject_invalid`, `:vitsme_refused` and `:vitsme_unavailable`, and
  `:stops_invalid` on a trip, with the generator's messages for them.
- `OmniAuth::Vitsme::Test.id_token(uid)`: mocked credentials now carry an ID token naming the mocked uid.
- data/claims.json, catalog version 4: the refusals `subject_required` and `subject_invalid`, a `trips`
  section, and `name__full` marked deprecated.

### Deprecated

- `name__full`: ask for `full_name__intl` (the default) or `full_name__local`. Naming it warns at boot.
  vits.me still answers it for a site that holds it.

## [0.6.0] - 2026-11-21

### Added

- The `full_name__local` and `full_name__intl` scopes: a full name in the person's own language and
  script, and in its international variant (English, capitalized, Latin letters with dashes and apostrophes,
  no accents). The person may leave out given names or show them as initials, keeping one written out.
- The `portrait` scope: the person's photo, the first picture claim. `extra.claims["portrait"]` is an
  `OmniAuth::Vitsme::Image` (`content_type`, `width`, `height`, `data`, `io`), decoded from the strict-base64
  JPEG vits.me sends whole in UserInfo; anything else (another type, loose base64, over 200 KB) is dropped.
  It is kept out of `info` and `extra.raw_info`, and its bytes out of `inspect`. Enabled by vits.me per site,
  on request. `OmniAuth::Vitsme::Test` takes one as a claim.

## [0.5.0] - 2026-11-13

### Changed (breaking)

- Partners of vits.me (KNOTs) are asked directly, as their own OAuth servers, not through vits.me. The new
  `vitsme_partner` strategy pushes the request (RFC 9126) with PKCE and the person's hint, the vits.me ID
  token you kept for them encrypted to vits.me's `use: enc` key, and sends the person to the partner. The
  callback redeems the code and fetches the claims, verified against the partner's keys, issuer and your
  client id: `uid` is the partner's identifier for the person at your site, `extra.claims` the answer, and
  `credentials.refresh_token` is there when the partner keeps a standing consent.
- `OmniAuth::Vitsme::Partner`: `listing` and `trusted!` (vits.me's list of partners, and only active
  ones are asked or believed), `metadata`, `software_statement`, `register` (RFC 7591), `fresh_claims`.
- `OmniAuth::Vitsme::Events.verify!` now verifies a partner's event: `partner:` and `client_id:`, with
  the person named by the partner's own identifier (`sub_id` format `opaque`).
- `OmniAuth::Vitsme::Test.mock_partner` and `.partner_auth_hash`.

### Removed

- KNOT scopes on the vits.me sign-in (`knot:<knot>:<name>`), `extra.knot_claims`, `extra.knot_errors`,
  `OmniAuth::Vitsme::Knot` (`scopes`, `resolve`, `fresh_claims`) and `Test.mock_auth(knot_claims:)`:
  vits.me no longer introduces sites to partners or relays their events.


## [0.4.0] - 2026-11-10

### Added

- KNOT claims, from partner services. The gem knows no partner: any `knot:<knot>:<name>` scope passes
  the boot-time scope check, and vits.me refuses one your site wasn't granted. When UserInfo carries
  KNOT sources, the strategy fetches each partner's answer during the callback, verifies its signature
  against the source's `jwks_uri`, issuer, audience (your client_id) and `knot_txn`, and puts the claims
  in `extra.knot_claims` as sent. A partner that can't be asked shows in `extra.knot_errors` and doesn't
  fail the sign-in.
- `OmniAuth::Vitsme::Knot.scopes` reads the active KNOT scopes as vits.me describes them now (what each
  answer holds, and a documentation link).
- `OmniAuth::Vitsme::Knot.fresh_claims` asks for KNOT claims again without the person, while their
  standing consent holds, raising `ConsentRequired` once it doesn't.
- `OmniAuth::Vitsme::Events.verify!` verifies the change events vits.me pushes to a site's change
  notifications URL: `:claims_changed`, and `:consent_withdrawn` with a `reason` of `withdrawn` or
  `retired` (the partner or scope left).
- `OmniAuth::Vitsme::Test.mock_auth(knot_claims:)`.
- `data/claims.json` has a generic `knots` section and the introduction's 30-second lifetime
  (catalog 3). It lists no partner.

### Changed

- `extra.raw_info` no longer carries `_claim_names`, `_claim_sources` or `knot_txn`: they are spent
  during the callback.

## [0.3.0] - 2026-11-05

### Added

- vits.me can suspend a site. Its sign-ins come back as the new failure type `:site_suspended`
  (`vitsme_error=application_suspended`, in `data/claims.json`'s refusals), and the generator's
  locales carry a message for it that doesn't name vits.me.

### Changed

- Credentials no longer come from the vits.me team: any verified person registers a site at
  vits.me/developer. The README, AGENTS.md and the skill say how, including the testing and public
  states, loopback redirect URIs for local development, and the secret shown once. AGENTS.md adds that
  a site may ask only for the scopes it registered; vits.me now sends such a request back as
  `:invalid_scope`, listed in the README's failure types.

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
