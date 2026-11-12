# frozen_string_literal: true

require 'securerandom'
require 'omniauth'
require 'omniauth/vitsme'

module OmniAuth
  module Vitsme
    # Test helpers for apps that sign people in with vits.me. Not loaded by default:
    #
    #   require 'omniauth/vitsme/test'
    #   OmniAuth.config.test_mode = true
    #   OmniAuth::Vitsme::Test.mock_auth(claims: { age__over_18: true })              # provider :vitsme
    #   OmniAuth::Vitsme::Test.mock_auth(:verify, uid: person.vitsme_uid, claims: { name: 'Jane D.' })
    #   OmniAuth::Vitsme::Test.mock_failure(:vitsme, :nationality_gate_refused)
    #   OmniAuth::Vitsme::Test.mock_partner(:contacts, partner: 'https://contacts.example', claims: { email: [...] })
    #
    # The auth hash is built by the same code as the real strategy's (AuthShape), so `info`, `extra`
    # and the typed claims look exactly as they will in production. Test mode skips the trip to vits.me
    # but still runs the strategy's identity checks (expected_uid, require_verified) on the mock: mock
    # someone other than the signed-in person to see :identity_mismatch. mock_failure is for refusals
    # only vits.me makes (:nationality_gate_refused, :site_suspended, :access_denied).
    module Test
      module_function

      # A plausible private uid. Real ones are opaque; never derive anything from them.
      def uid(identity = :solid)
        "#{identity == :fluid ? AuthShape::FLUID_PREFIX : AuthShape::SOLID_PREFIX}#{SecureRandom.alphanumeric(52).downcase}"
      end

      # The UserInfo response vits.me would send: identity claims plus the disclosure claims given.
      def raw_info(uid:, claims: {}, defunct_uids: [], fluid_uids: [])
        claims = claims.transform_keys(&:to_s)
        unknown = claims.keys.reject { |name| Catalog.claim(name) }
        raise ArgumentError, "omniauth-vitsme: unknown claim(s) #{unknown.join(', ')}" unless unknown.empty?

        info = { 'sub' => uid }
        info['solid'] = uid if AuthShape.identity_kind(uid) == :solid
        info['defunct_solids'] = defunct_uids unless defunct_uids.empty?
        info['fluid'] = fluid_uids unless fluid_uids.empty?
        info.merge(claims)
      end

      def auth_hash(provider = :vitsme, identity: :solid, uid: nil, claims: {}, defunct_uids: [], fluid_uids: [])
        uid ||= self.uid(identity)
        raw = raw_info(uid: uid, claims: claims, defunct_uids: defunct_uids, fluid_uids: fluid_uids)
        OmniAuth::AuthHash.new(
          provider: provider.to_s,
          uid: uid,
          info: AuthShape.info(uid, raw),
          credentials: { id_token: 'test.id.token', scope: 'openid' },
          extra: AuthShape.extra(uid, raw)
        )
      end

      # Makes the next callback for `provider` succeed with this person.
      def mock_auth(provider = :vitsme, **)
        OmniAuth.config.mock_auth[provider.to_sym] = auth_hash(provider, **)
      end

      # A partner's answer (the vitsme_partner strategy), as your callback gets it. `claims` is whatever the
      # partner says, passed through as it is; `subject` stands for the partner's identifier for the person.
      def partner_auth_hash(provider, partner:, claims: {}, subject: nil, refresh_token: nil)
        claims = claims.transform_keys(&:to_s)
        subject ||= "ks_#{SecureRandom.urlsafe_base64(32)}"
        OmniAuth::AuthHash.new(provider: provider.to_s, uid: subject, info: {},
                               credentials: { refresh_token: refresh_token }.compact,
                               extra: { partner: partner, claims: claims, scopes: claims.keys })
      end

      # Makes the next callback for a vitsme_partner `provider` succeed with this answer.
      def mock_partner(provider, **)
        OmniAuth.config.mock_auth[provider.to_sym] = partner_auth_hash(provider, **)
      end

      # Makes the next callback for `provider` fail with `type` (e.g. :identity_mismatch, :not_signed_in,
      # :unverified_identity, :nationality_gate_refused, :site_suspended, :access_denied).
      def mock_failure(provider = :vitsme, type = :access_denied)
        OmniAuth.config.mock_auth[provider.to_sym] = type.to_sym
      end
    end
  end
end
