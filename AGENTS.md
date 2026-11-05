# AGENTS.md — omniauth-vitsme

You are helping someone sign people in with vits.me, or ask vits.me about them, from a Ruby/Rails
app. These rules are not style preferences: breaking one leaks a private identifier or credits one
person's verified details to another.

## Choosing what to ask for

- Scopes, claims, types, value formats and gates are all in [data/claims.json](data/claims.json).
  Read it instead of guessing; an unknown scope raises at boot.
- Ask for the least that answers the question: `age__over_18` rather than `birthdate`, a gate
  rather than `nationality` when "is this person Israeli?" is all you need.
- vits.me has no email, phone, picture or username claim. Ask the person for anything else.

## Rules

1. **The uid is private.** `auth.uid` (`sub`), `extra.lookup_uids` and `extra.fluid_uids` are
   per-site secrets. Store them server-side as the lookup key, and never render, log, put in a URL,
   federate, or derive a handle or email from them.
2. **Don't log the auth hash.** `request.env["omniauth.auth"]` holds the uid and every shared detail.
3. **Follow-up questions about a signed-in person need `expected_uid`.** A provider that verifies a
   name, an age or a nationality of someone already signed in to the app must set
   `expected_uid: ->(env) { ...the signed-in person's stored uid... }`. Without it, whoever signs in
   at vits.me gets their details credited to the signed-in account. Don't set it on the sign-in
   provider: there is nobody to expect yet.
4. **Missing is not false.** Any disclosure claim may be absent: not shared, not held, or hidden.
   Branch on `true` / `false` / absent, and never default a missing boolean to `false`.
5. **A gate emits nothing.** `nationality_gate:` admits only verified nationals. Success is the
   answer, and a refusal is `:nationality_gate_refused`. It can't be combined with the `fluid` scope.
6. **`fluid_` means unverified.** Without the `fluid` scope you never see one. With it, give such
   people a limited, tentative account and merge it when `extra.fluid_uids` shows up on a verified
   sign-in.
7. **Read everything in the callback.** Tokens live 5 seconds and there is no refresh token. Nothing
   can be fetched later.
8. **Find returning people by `extra.lookup_uids`** (plus `fluid_uids` with FLUID), current first, and
   move a record found under an older uid to `auth.uid`.
9. **User-facing copy says "verified"**, not "vits.me-verified". There is no need to name vits.me to
   end users.
10. **Handle every failure type** in [README.md#failure-types](README.md#failure-types):
    `not_signed_in`, `identity_mismatch`, `unverified_identity`, `nationality_gate_refused`,
    `site_suspended`, `access_denied`.
11. **Ask only for scopes the site registered.** Its page at vits.me/developer sets which it may ask
    for, and vits.me refuses a request for any other. `il_government_id_number` is enabled by vits.me
    on request, per site.

## Doing the work

- Credentials: the person registers the site at [vits.me/developer](https://vits.me/developer) with
  their verified account. You can't do it for them: it takes their pincode, and the secret is shown
  to them once.
- Rails: `bin/rails g omniauth_vitsme:install` (see `--help`) writes the initializer, controller,
  locales, button and migration correctly. Prefer it to hand-writing.
- Tests: `require "omniauth/vitsme/test"`, then `OmniAuth::Vitsme::Test.mock_auth(...)` /
  `.mock_failure(...)`. Mocks have the real shape; unknown claims raise.
- A worked app: [examples/rails/app.rb](examples/rails/app.rb).
- The skill [.claude/skills/vitsme-integrate/SKILL.md](.claude/skills/vitsme-integrate/SKILL.md) walks
  through adding vits.me to an app end to end.

## Working on this gem

- `bundle exec rspec && bundle exec rubocop` must pass. The suite boots the example Rails app.
- `data/claims.json` mirrors the vits.me server (`config/initializers/doorkeeper*.rb` in the
  mattyr mono-repo). Change them together, and keep `spec/omniauth/vitsme/catalog_spec.rb`'s scope
  list in step.
- `AuthShape` builds the auth hash for both the strategy and the test helper. Change the shape there
  only.
- Pre-1.0: breaking changes are fine. Record them in CHANGELOG.md.
