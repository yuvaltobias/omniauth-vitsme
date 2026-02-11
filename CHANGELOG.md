# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-11

### Added

- Initial release
- OmniAuth strategy for vits.me OpenID Connect provider
- OIDC discovery enabled by default
- RS256 token signing
- Support for vits.me scopes: openid, name, nationality, age verification, birthday
- Convenience `client_id` / `client_secret` top-level options
