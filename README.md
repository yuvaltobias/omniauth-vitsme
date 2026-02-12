# OmniAuth vits.me

OmniAuth strategy for [vits.me](https://vits.me) (itsme), global digital identity verification platform.

Wraps [omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect) with vits.me-specific defaults so you only need to supply `client_id` and `client_secret`.

## Installation

Add to your Gemfile:

```ruby
gem "omniauth-vitsme", "~> 0.1"
```

Then run:

```
bundle install
```

## Usage

### Rails (Rack middleware)

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :vitsme,
    client_id: ENV["VITSME_CLIENT_ID"],
    client_secret: ENV["VITSME_CLIENT_SECRET"]
end
```

### With additional scopes

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :vitsme,
    client_id: ENV["VITSME_CLIENT_ID"],
    client_secret: ENV["VITSME_CLIENT_SECRET"],
    scope: [:openid, :name, :age__over_18, :nationality]
end
```

### Devise integration

```ruby
Devise.setup do |config|
  config.omniauth :vitsme,
    client_id: ENV["VITSME_CLIENT_ID"],
    client_secret: ENV["VITSME_CLIENT_SECRET"],
    scope: [:openid, :name]
end
```

## Available Scopes

| Scope | Description |
|---|---|
| `openid` | Required. Returns the subject identifier (`sub`). |
| `name` | Given name and family name |
| `name__full` | Full name as a single string |
| `nationality` | ISO country code |
| `nationality__in_eu` | Whether the user is an EU national |
| `birthday` / `birthdate` | Date of birth |
| `birthyear` | Year of birth |
| `age__over_13` | Age verification (13+) |
| `age__over_18` | Age verification (18+) |
| `age__over_21` | Age verification (21+) |

## Auth Hash

The auth hash returned in the callback looks like:

```ruby
{
  provider: "vitsme",
  uid: "pairwise-subject-identifier",
  info: {
    name: "Jane Doe",
    first_name: "Jane",
    last_name: "Doe",
    email: "jane@example.com",
    birthday: "1990-01-15",
    nationality: "IL",
    age_over_13: true,
    age_over_18: true,
    age_over_21: true
  },
  credentials: {
    id_token: "eyJ...",
    token: "access_token_value",
    refresh_token: "refresh_token_value",
    expires_in: 3600,
    scope: "openid name"
  },
  extra: {
    raw_info: {
      sub: "pairwise-subject-identifier",
      name: "Jane Doe",
      # ... all raw claims from the userinfo endpoint
    }
  }
}
```

Only requested scopes will appear in `info`. Nil values are omitted via `.compact`.

Note: vits.me uses **pairwise subject identifiers** -- the same person will have a different `uid` for each registered client application.

## Configuration

| Option | Default | Description |
|---|---|---|
| `client_id` | *required* | Your vits.me client ID |
| `client_secret` | *required* | Your vits.me client secret |
| `scope` | `[:openid]` | OIDC scopes to request |
| `discovery` | `true` | Fetch endpoints from `.well-known/openid-configuration` |
| `issuer` | `https://vits.me` | OIDC issuer URL |
| `response_type` | `code` | OAuth response type (Authorization Code Flow) |

## Development

```
bundle install
bundle exec rspec
bundle exec rubocop
bundle exec rake        # runs both
```

## License

MIT License. See [LICENSE.txt](LICENSE.txt).
