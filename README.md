# OmniAuth vits.me

Sign people in with [vits.me](https://vits.me), ask about details they have verified there (a name, an
age, a nationality), and admit only verified nationals of chosen countries. An OmniAuth strategy on top
of [omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect), with the vits.me
rules built in.

> **Agents:** read [AGENTS.md](AGENTS.md) first. Every scope and claim is in
> [data/claims.json](data/claims.json).

- [Quick start](#quick-start)
- [Environments](#environments)
- [Claims](#claims)
- [Verifying a signed-in person](#verifying-a-signed-in-person)
- [Gated communities](#gated-communities)
- [Unverified (FLUID) identities](#unverified-fluid-identities)
- [Finding a returning person](#finding-a-returning-person)
- [Failure types](#failure-types)
- [The auth hash](#the-auth-hash)
- [Operational notes](#operational-notes)
- [Privacy rules](#privacy-rules)
- [Testing](#testing)
- [Options](#options)

## Quick start

```ruby
# Gemfile
gem "omniauth-vitsme", "~> 0.5"
gem "omniauth-rails_csrf_protection" # OmniAuth 2 starts sign-in by POST only
```

The generator writes everything below: an initializer, a callbacks controller, failure messages
(en/he), a sign-in button, routes, and a migration adding a unique `vitsme_uid` column.

```
bin/rails g omniauth_vitsme:install [--model=User] [--scope=name] [--verify=age__over_18] [--gate=IL] [--fluid]
```

Or by hand:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :vitsme,
    client_id: ENV["VITSME_CLIENT_ID"],
    client_secret: ENV["VITSME_CLIENT_SECRET"],
    environment: Rails.env.production? ? :production : :development
end
```

```erb
<%= button_to "Sign in", "/auth/vitsme", method: :post, data: { turbo: false } %>
```

Register your site at [vits.me/developer](https://vits.me/developer): any verified person can, after
accepting the developer terms. Add `https://<your host>/auth/vitsme/callback` (and one callback per
extra provider) as redirect URIs, plus `http://127.0.0.1:<port>/auth/vitsme/callback` for local
development. The client secret is shown once, when it is created or rotated. A new site starts in
testing: it works end to end, and the sign-in screen tells people it is still being tested until you
add a privacy policy URL and a contact and make it public.

## Environments

| `environment:` | Issuer |
|---|---|
| `:production` (default) | `https://vits.me` |
| `:staging` | `https://staging.vits.me` |
| `:development` / `"test"` | `https://vitsme.localhost` (local, mkcert certificate) |

`OmniAuth::Vitsme.issuer(Rails.env)` gives the same mapping. An explicit `issuer:` wins.

## Claims

Ask for a claim by its scope: `scope: %i[openid age__over_18 nationality]`. `openid` is always added.
An unknown scope raises `ArgumentError` when the app boots. The full list, with types and value
formats, is [data/claims.json](data/claims.json).

| Scope = claim | Type in `extra.claims` | Example |
|---|---|---|
| `name` | String: one name at the detail the person chose | `"Jane"`, `"J. D."`, `"Jane Doe"` |
| `name__full` | String | `"Jane Doe"` |
| `nationality` | String, ISO 3166-1 alpha-2 | `"IL"` |
| `nationality__in_eu`, `__in_eea`, `__in_esm`, `__gdpr_compliant` | Boolean | `true` |
| `il_government_id_number` | String | (sensitive: ask only with a legal need) |
| `age` | String: a threshold, generation, range or years | `"over_18"`, `"gen_x"`, `"25_to_34"`, `"37"` |
| `age__years` | Integer | `37` |
| `age__range` | String | `"25_to_34"` |
| `age__over_13`, `__over_18`, `__over_21` | Boolean | `true` |
| `birthdate` | String `YYYY-MM-DD` | `"1990-01-15"` |
| `birthday` | String `M-D` or `YYYY-MM-DD`, as the person chose | `"1-15"` |
| `birthyear` | String `YYYY` | `"1990"` |

**The person chooses.** On vits.me's consent screen the person picks what to share for each scope,
at the level of detail they prefer, or nothing at all.

**Missing is not false.** A claim may be absent even when its scope was granted: the person shared
nothing, holds no such detail, or hid it. `extra.claims["age__over_18"]` is `true`, `false`, or not
there. Treat "not there" as "unknown", never as "no":

```ruby
case auth.extra.claims["age__over_18"]
when true  then admit
when false then refuse
else            ask_them_to_share_it
end
```

There is no email, phone, picture or username. If you need a public handle, ask the person for one.

## Verifying a signed-in person

vits.me signs in **whoever is at its keyboard** and answers about them. A provider that asks about the
person *already signed in to your app* must make sure the answer is about them, or one person's
verified details get credited to another. `expected_uid` does that:

```ruby
provider :vitsme,
  name: :vitsme_verify,
  client_id: ENV["VITSME_CLIENT_ID"], client_secret: ENV["VITSME_CLIENT_SECRET"],
  scope: %i[openid age__over_18],
  expected_uid: ->(env) { User.find_by(id: env["rack.session"]["user_id"])&.vitsme_uid }
```

- Nobody signed in: the request fails `:not_signed_in` without leaving your app.
- vits.me is told whom you expect (the standard OpenID Connect `claims` sub request). It opens the
  pincode page on that person's account and refuses anyone else (`:identity_mismatch`).
- The callback checks again, in the middleware, before your controller runs: the answer must be about
  `expected_uid` or a uid vits.me lists in `defunct_solids`. Otherwise it fails `:identity_mismatch`.
- With `expected_uid` set, a pending (`fluid_`) identity fails `:unverified_identity`
  (`require_verified: false` turns that off).

Use `expected_uid` only for these follow-up questions. At sign-in there is nobody to expect yet.

## Gated communities

```ruby
provider :vitsme, client_id: ..., client_secret: ..., nationality_gate: %w[IL]
```

Only verified people holding one of the listed nationalities finish signing in. Several codes mean
any of them. vits.me asks the person to consent to this check. **The gate sends no claim back**: a
successful sign-in is the answer. Add the `nationality` scope if you also want the value. A person
who doesn't pass returns as `:nationality_gate_refused`, and no account is created.

A gate admits verified people only, so it can't be combined with the `fluid` scope (that raises at
boot). Make your gated sign-in button look different from an ordinary one, so people know before they
start. To build a community that way, follow madon's lead: gate the sign-in, then ask the new member
to pick a public handle. Never derive the handle from the uid.

## Unverified (FLUID) identities

By default only verified people can sign in. With `scope: %i[openid fluid]`, people whose verification
is still pending can sign in too:

- `uid` starts with `fluid_`, `extra.identity` is `:fluid`, and `info.verified` is `false`.
- A pending identity lasts one week. Give it a limited, tentative account.
- When the person is verified, a later sign-in returns their `solid_` uid with the pending uids in
  `extra.fluid_uids`. Merge the tentative account into the verified one, and drop tentative accounts
  nobody claimed after a week.

## Partner services (KNOTs)

Some facts come from partner services rather than vits.me: the organizations a person acts for, the groups
they belong to, a verified email address. Each partner is an OAuth server of its own. Your site asks it
directly, as its client, and gets the answer straight from it. vits.me is not on the way: it signs the
person in at the partner, with their pincode, and makes sure it is the person your site means. Partners
come and go, so this gem knows none of them. vits.me lists the active ones, and each partner documents its
own scopes:

```ruby
OmniAuth::Vitsme::Partner.listing(OmniAuth::Vitsme.issuer(:production))
# [{ "name" => "…", "issuer" => "https://…", "status" => "active", "scopes" => [{ "name" => "…", "title" => {…}, … }] }]
```

**Keep the ID token.** When your site signs a person in, keep `auth.credentials.id_token` with them. It is
the hint you send a partner: encrypted to vits.me, so the partner cannot read it, and vits.me then lets
nobody but that person answer. Without one there is nobody to ask about.

**Register your site's callback for the partner** among its redirect addresses at vits.me/developer:
partners send codes only to an address vits.me lists for your site. A partner that takes registrations
(its metadata has a `registration_endpoint`) wants your site registered there once, with a software
statement vits.me signs for it:

```ruby
statement = OmniAuth::Vitsme::Partner.software_statement(vitsme_issuer: OmniAuth::Vitsme.issuer(:production),
                                                         client_id: ENV["VITSME_APP_ID"],
                                                         client_secret: ENV["VITSME_APP_SECRET"],
                                                         audience: "https://partner.example")
OmniAuth::Vitsme::Partner.register(partner: "https://partner.example", software_statement: statement,
                                   events_uri: "https://your.site/partner/events")
# => { "client_id" => …, "client_secret" => "…" }   keep the secret: it is shown once
```

A partner that takes none (`software_statement_required` in its metadata) gets a fresh statement with each
request, which the strategy fetches for you.

**Ask from a button of your own**, when you need what the partner holds, with your own explanation:

```ruby
provider :vitsme_partner, name: :contacts,
                          partner: "https://partner.example",          # its issuer, as vits.me lists it
                          scope: %w[email],                             # its own scope names
                          client_id: ENV["VITSME_APP_ID"], client_secret: ENV["VITSME_APP_SECRET"],
                          partner_secret: ENV["PARTNER_SECRET"],        # only if you registered there
                          id_token: ->(env) { Person.find_by(id: env["rack.session"]["person_id"])&.vitsme_id_token }
```

The person signs in at the partner with their pincode, sees what your site asks for, turns on what to give
and selects which. The callback hands you the answer, verified:

```ruby
auth.uid                        # the partner's own identifier for the person at your site (never their vits.me uid)
auth.extra.claims               # { "<scope>" => <the partner's answer> }, an empty list for one they did not give
auth.credentials.refresh_token  # when the partner keeps a standing consent; nil otherwise
```

Failures are `:not_signed_in` (no ID token), `:partner_untrusted` (vits.me does not list it as active),
`:partner_unavailable`, `:partner_refused`, `:partner_mixup` (an answer from another issuer) and
`:access_denied`.

**Fresh claims, without the person.** While their standing consent at the partner holds:

```ruby
result = OmniAuth::Vitsme::Partner.fresh_claims(partner: "https://partner.example", client_id: ENV["VITSME_APP_ID"],
                                                partner_secret: ENV["PARTNER_SECRET"], refresh_token: person.partner_refresh_token,
                                                vitsme_issuer: OmniAuth::Vitsme.issuer(:production))
result.claims         # as above
result.refresh_token  # keep it: the one you used is spent
# raises OmniAuth::Vitsme::Partner::Refused once the consent no longer holds: let go of what you had
```

**Change events.** A partner that keeps standing consents POSTs to the events address you registered
with it when something changed for someone, or they stopped it. Verify each one:

```ruby
class PartnerEventsController < ActionController::API
  def create
    event = OmniAuth::Vitsme::Events.verify!(request.raw_post, partner: "https://partner.example",
                                             client_id: ENV["VITSME_APP_ID"], environment: Rails.env)
    link = PartnerLink.find_by(subject: event.uid)   # the uid the partner's answer gave you
    case event.type
    when :claims_changed then RefreshPartnerClaimsJob.perform_later(link.id) if link
    when :consent_withdrawn then link&.destroy
    end
    head :accepted
  rescue OmniAuth::Vitsme::Events::Invalid
    head :bad_request
  end
end
```

## Finding a returning person

Look a person up by `extra.lookup_uids`, current uid first, plus `extra.fluid_uids` if you use FLUID.
A record found under an older uid belongs to this person: move it to `auth.uid`.

```ruby
uids = auth.extra.lookup_uids + auth.extra.fluid_uids
user = User.where(vitsme_uid: uids).min_by { |u| uids.index(u.vitsme_uid) }
user&.update!(vitsme_uid: auth.uid) unless user&.vitsme_uid == auth.uid
user ||= User.create!(vitsme_uid: auth.uid)
```

(vits.me lists superseded uids in `defunct_solids` for a year after a re-key.)

## Failure types

OmniAuth sends failures to `OmniAuth.config.on_failure` (in Rails, `/auth/failure?message=<type>`).

| Type | Meaning |
|---|---|
| `:not_signed_in` | `expected_uid` returned nothing: nobody is signed in to your app. |
| `:identity_mismatch` | The answer was about someone other than `expected_uid`, whether caught by vits.me or by the callback. |
| `:unverified_identity` | A pending (`fluid_`) identity, refused by `require_verified`. |
| `:nationality_gate_refused` | The person doesn't hold a nationality the gate requires (or is unverified). |
| `:site_suspended` | vits.me has suspended your site; nobody can sign in until it is lifted. Your site's page in the developer area says why. |
| `:invalid_scope` | The app asked for a scope its registration doesn't include. Tick it on your site's page at vits.me/developer (the Israeli ID number needs vits.me to enable it). |
| `:access_denied` | Any other refusal, e.g. the person cancelled. |
| others | From omniauth_openid_connect: `:csrf_detected`, `:invalid_grant`, `:timeout`, … |

## The auth hash

```ruby
{
  provider: "vitsme",
  uid: "solid_…",                      # private: store, never show or log
  info: { name: "Jane D.", nationality: "IL", verified: true },  # only what was shared
  credentials: { id_token: "…", scope: "openid name" },          # no refresh token
  extra: {
    identity: :solid,                  # or :fluid
    lookup_uids: ["solid_…", "solid_<earlier>"],
    fluid_uids: [],
    claims: { "name" => "Jane D.", "age__over_18" => true },     # typed, shared claims only
    raw_info: { "sub" => "solid_…", … }                          # the UserInfo response
  }
}
```

`info.name` is the shared `name` (or `name__full`). OmniAuth always includes the key, which may be nil.

## Operational notes

- **Read everything in the callback.** Authorization codes, access tokens and ID tokens live for
  **5 seconds** and there is no refresh token. The strategy redeems the code and fetches UserInfo at
  once. Keep your server's clock in sync (NTP): a few seconds of skew fails ID-token validation.
- **Every sign-in asks for the pincode.** A regular person's vits.me session lasts one site sign-in,
  so there is no single sign-on between sites and `prompt=none` cannot succeed. `prompt: :login` is the
  default. A "verify" round-trip asks for the pincode too.
- **No logout endpoint.** Sign people out of your app; there's nothing to end at vits.me.
- **PKCE (S256) is on** by default, alongside the client secret.
- **Claims arrive from UserInfo, not the ID token.** The strategy handles this.

## Privacy rules

- The uid (`sub`), `lookup_uids` and `fluid_uids` are **private, per-site identifiers**. Treat them
  like session tokens: store them server-side as the lookup key, and **never** render them, log them,
  put them in a URL, federate them, or derive a username, handle or email from them.
- Don't log `request.env["omniauth.auth"]`: it holds the uid and everything the person shared.
- Ask for the least you need. `age__over_18` answers "is this an adult?". `birthdate` answers far more.
- In copy your users read, call people "verified". There is no need to name vits.me.

## Testing

```ruby
require "omniauth/vitsme/test"

OmniAuth.config.test_mode = true
OmniAuth::Vitsme::Test.mock_auth(claims: { age__over_18: true })                 # :vitsme
OmniAuth::Vitsme::Test.mock_auth(:vitsme_verify, uid: user.vitsme_uid, claims: { name: "Jane D." })
OmniAuth::Vitsme::Test.mock_auth(identity: :fluid)                               # pending signup
OmniAuth::Vitsme::Test.mock_auth(:vitsme_verify, uid: someone_else_uid)                   # → :identity_mismatch
OmniAuth::Vitsme::Test.mock_failure(:vitsme, :nationality_gate_refused)
```

Mocks are built by the same code as real sign-ins, so they have the real shape and types, and
unknown claims raise. Test mode skips the round trip to vits.me, but the strategy's identity checks
still run on the mock. A verify provider's `expected_uid` and `require_verified` judge the mocked
answer exactly as they would a real one: mock the signed-in person's uid to pass, or someone else's
to see `:identity_mismatch`. A mocked earlier uid (`defunct_uids:`) matches as it does in
production. `mock_failure` simulates refusals that only vits.me can make, such as
`:nationality_gate_refused`, `:site_suspended` or `:access_denied`.

[examples/rails/app.rb](examples/rails/app.rb) is a one-file Rails app using sign-in, a gate and
verification. The test suite boots it against a stubbed vits.me.

## Options

| Option | Default | |
|---|---|---|
| `client_id`, `client_secret` | required | From your site's page at [vits.me/developer](https://vits.me/developer) |
| `environment` | `:production` | `:production`, `:staging`, `:development` |
| `issuer` | from `environment` | |
| `scope` | `[:openid]` | Validated against [data/claims.json](data/claims.json) |
| `nationality_gate` | `[]` | ISO alpha-2 codes, e.g. `%w[IL]` |
| `expected_uid` | `nil` | `->(env) { uid }` for follow-up questions about a signed-in person |
| `require_verified` | on when `expected_uid` is set | Refuse `fluid_` identities |
| `send_expected_uid` | `true` | Tell vits.me whom you expect |
| `prompt` | `:login` | |
| `pkce` | `true` | S256 |
| `name` | `"vitsme"` | Set a different name for each additional provider |

Everything else is passed to omniauth_openid_connect.

## Development

```
bundle install
bundle exec rspec     # strategy, catalog, generator, and the example Rails app
bundle exec rubocop
```

The catalog mirrors the vits.me server. When vits.me adds a scope, it lands in `data/claims.json` in
the same change (vits.me's `docs/adding-vitsme-scope.md`).

## License

MIT License. See [LICENSE.txt](LICENSE.txt).
