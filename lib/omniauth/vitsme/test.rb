# frozen_string_literal: true

require 'base64'
require 'json'
require 'securerandom'
require 'omniauth'
require 'omniauth/vitsme'

module OmniAuth
  module Vitsme
    # Test helpers for apps that sign people in with vits.me. Not loaded by default:
    #
    #   require 'omniauth/vitsme/test'
    #   OmniAuth.config.test_mode = true
    #   OmniAuth::Vitsme::Test.mock_auth(uid: uid)                                    # provider :vitsme, a sign-in
    #   OmniAuth::Vitsme::Test.mock_auth(:verify, uid: person.vitsme_uid, claims: { name: 'Jane D.' })   # an ask
    #   OmniAuth::Vitsme::Test.mock_failure(:vitsme, :gate_refused)
    #   OmniAuth::Vitsme::Test.mock_partner(:contacts, partner: 'https://contacts.example', claims: { email: [...] })
    #   OmniAuth::Vitsme::Test.mock_trip(:verify_and_groups, uid: person.vitsme_uid, claims: { age__over_18: true },
    #                                    stops: [{ partner: 'https://groups.example', claims: { 'roles' => [] } }])
    #
    # The auth hash is built by the same code as the real strategy's (AuthShape), so `info`, `extra`
    # and the typed claims look exactly as they will in production, and `credentials.id_token` names the uid
    # as a real one does (`ask_about:` may return it). Test mode skips the trip to vits.me
    # but still runs the strategy's identity checks (ask_about, require_verified) on the mock: mock
    # someone other than the signed-in person to see :identity_mismatch. mock_failure is for refusals
    # only vits.me makes (:gate_refused, :site_suspended, :access_denied).
    module Test
      module_function

      # A plausible private uid. Real ones are opaque; never derive anything from them.
      def uid(identity = :solid)
        "#{identity == :fluid ? AuthShape::FLUID_PREFIX : AuthShape::SOLID_PREFIX}#{SecureRandom.alphanumeric(52).downcase}"
      end

      # The UserInfo response vits.me would send: identity claims plus the disclosure claims given.
      def raw_info(uid:, claims: {}, defunct_uids: [], fluid_uids: [])
        # A picture is given as an OmniAuth::Vitsme::Image and sent as vits.me sends it.
        claims = claims.transform_keys(&:to_s)
                       .transform_values { |value| value.respond_to?(:to_claim) ? value.to_claim : value }
        unknown = claims.keys.reject { |name| Catalog.claim(name) }
        raise ArgumentError, "omniauth-vitsme: unknown claim(s) #{unknown.join(', ')}" unless unknown.empty?

        info = { 'sub' => uid }
        info['solid'] = uid if AuthShape.identity_kind(uid) == :solid
        info['defunct_solids'] = defunct_uids unless defunct_uids.empty?
        info['fluid'] = fluid_uids unless fluid_uids.empty?
        info.merge(claims)
      end

      # An ID token naming `uid`, as your app keeps it and `ask_about:` may return it. Unsigned: a stand-in
      # that OmniAuth::Vitsme::Subject reads as it reads a real one.
      def id_token(uid, **claims)
        part = ->(hash) { Base64.urlsafe_encode64(JSON.generate(hash), padding: false) }
        header = part.call(alg: 'none', typ: 'JWT')
        payload = part.call({ iss: 'https://vits.me', sub: uid }.merge(claims))
        "#{header}.#{payload}."
      end

      def auth_hash(provider = :vitsme, identity: :solid, uid: nil, claims: {}, defunct_uids: [], fluid_uids: [])
        uid ||= self.uid(identity)
        raw = raw_info(uid: uid, claims: claims, defunct_uids: defunct_uids, fluid_uids: fluid_uids)
        OmniAuth::AuthHash.new(
          provider: provider.to_s,
          uid: uid,
          info: AuthShape.info(uid, raw),
          credentials: { id_token: id_token(uid), scope: 'openid' },
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

      # A whole trip's answer (the vitsme_trip strategy): vits.me's, as auth_hash builds it, and each stop's in
      # `extra.stops`. A stop is { partner:, claims:, subject:, refresh_token: } or { partner:, error: }.
      def trip_auth_hash(provider, stops:, **)
        auth = auth_hash(provider, **)
        auth.extra.stops = stops.map { |stop| trip_stop(stop.transform_keys(&:to_s)) }
        auth
      end

      def trip_stop(stop)
        return stop.slice('partner', 'error') if stop['error']

        claims = stop.fetch('claims', {}).transform_keys(&:to_s)
        { 'partner' => stop.fetch('partner'), 'uid' => stop['subject'] || "ks_#{SecureRandom.urlsafe_base64(32)}",
          'claims' => claims, 'scopes' => claims.keys, 'refresh_token' => stop['refresh_token'] }.compact
      end

      # Makes the next callback for a vitsme_trip `provider` succeed with this answer.
      def mock_trip(provider, **)
        OmniAuth.config.mock_auth[provider.to_sym] = trip_auth_hash(provider, **)
      end

      # Makes the next callback for `provider` fail with `type` (e.g. :identity_mismatch, :not_signed_in,
      # :unverified_identity, :gate_refused, :site_suspended, :access_denied).
      def mock_failure(provider = :vitsme, type = :access_denied)
        OmniAuth.config.mock_auth[provider.to_sym] = type.to_sym
      end
    end
  end
end
