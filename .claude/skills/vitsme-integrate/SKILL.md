---
name: vitsme-integrate
description: Add vits.me sign-in, verification of a signed-in person's details (name, age, nationality), or a nationality-gated sign-up to a Ruby on Rails app with the omniauth-vitsme gem. Use when someone asks to "sign in with vits.me", "verify users' age/name with vits.me", or "only let verified <nationals> join".
---

# Add vits.me to a Rails app

Read [AGENTS.md](../../../AGENTS.md) first: its ten rules apply to every step. Scopes and claims are
listed in [data/claims.json](../../../data/claims.json).

## 1. Decide what the app needs

Ask the person (or infer from their request) which of these they want. It can be more than one:

| Need | Configuration |
|---|---|
| Sign people in | `provider :vitsme` (scope `openid`) |
| Learn something at sign-in | add disclosure scopes, e.g. `--scope=age__over_18` |
| Verify a detail about someone already signed in | a second provider with `expected_uid` (`--verify=...`) |
| Only verified nationals of X may join | `nationality_gate: %w[X]` (`--gate=X`) |
| Let people in before their verification finishes | the `fluid` scope (`--fluid`); not with a gate |

Pick the narrowest scope that answers the question, e.g. `age__over_18`, not `birthdate`.

## 2. Install

```bash
bundle add omniauth-vitsme omniauth-rails_csrf_protection
bin/rails g omniauth_vitsme:install --model=User [--scope=...] [--verify=...] [--gate=IL] [--fluid]
bin/rails db:migrate
```

If the app already has OmniAuth or a sign-in controller, read the generated files and merge them
into the existing ones rather than keeping two. The essentials:
- `config/initializers/omniauth_vitsme.rb`: providers.
- `VitsmeCallbacksController#sign_in`: looks people up by `extra.lookup_uids` (+ `fluid_uids`).
- `#verify`: runs only after the identity check.
- `#failure`: maps failure types to messages.
- The `vitsme_uid` column: unique and private.

## 3. Wire the UI

- Render `vitsme/sign_in` where people sign in. OmniAuth 2 starts by POST (`button_to`).
- A gated sign-in should look different from an ordinary one and say who can join.
- Copy says "verified", not "vits.me-verified".
- If the app needs a public username, ask the person for one after their first sign-in. Never derive
  it from the uid.

## 4. Use the answers correctly

- `auth.extra.claims["age__over_18"]` is `true`, `false`, or **absent**. Handle all three.
- Store only what the app needs. Never log `request.env["omniauth.auth"]` and never show the uid.

## 5. Test

```ruby
require "omniauth/vitsme/test"
OmniAuth.config.test_mode = true
OmniAuth::Vitsme::Test.mock_auth(claims: { age__over_18: true })
OmniAuth::Vitsme::Test.mock_failure(:vitsme_verify, :identity_mismatch)
```

Write request specs covering:
- a first sign-in, which creates the person;
- a returning person found under an earlier uid (`defunct_uids:`), which moves their record;
- a successful verify;
- each failure type the app can meet.

## 6. Hand over

Tell the person they need client credentials and redirect-URI registration from the vits.me team.
The generator prints the exact callback URLs. Set `VITSME_CLIENT_ID` / `VITSME_CLIENT_SECRET`, and
use `environment: :development` against a local vits.me (`https://vitsme.localhost`).
