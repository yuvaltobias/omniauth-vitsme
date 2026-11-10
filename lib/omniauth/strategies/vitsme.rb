# frozen_string_literal: true

require 'json'
require 'uri'
require 'omniauth_openid_connect'
require 'omniauth/vitsme/issuers'
require 'omniauth/vitsme/catalog'
require 'omniauth/vitsme/auth_shape'

module OmniAuth
  module Strategies
    # Sign in with vits.me, or ask vits.me about someone already signed in to your app.
    #
    #   provider :vitsme, client_id: ..., client_secret: ...,
    #            scope: %i[openid age__over_18],          # checked against data/claims.json at boot
    #            nationality_gate: %w[IL],                # optional: only verified IL nationals get through
    #            expected_uid: ->(env) { ... },           # "details about a signed-in person" only
    #            require_verified: true                   # refuse pending (fluid_) identities
    #
    # A KNOT scope (knot:<knot>:<name>) asks a partner service; its claims arrive verified in
    # extra.knot_claims (OmniAuth::Vitsme::Knot).
    #
    # See README.md for the auth hash, the failure types and the rules (the uid is private).
    class Vitsme < OpenIDConnect
      option :name, 'vitsme'

      option :environment, :production
      option :issuer, nil
      option :discovery, true
      option :client_signing_alg, :RS256
      option :scope, [:openid]
      option :response_type, 'code'
      option :response_mode, 'query'
      # Every vits.me sign-in asks for the pincode; a regular person's session there lasts one site sign-in.
      option :prompt, :login
      option :pkce, true

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: nil,
        host: nil,
        port: nil,
        authorization_endpoint: '/oauth/authorize',
        token_endpoint: '/oauth/token',
        userinfo_endpoint: '/oauth/userinfo',
        jwks_uri: '/oauth/discovery/keys',
        end_session_endpoint: nil
      }

      option :client_id, nil
      option :client_secret, nil

      # Nationalities a person must hold to finish signing in (gate scopes `openid_nationality__xx`).
      option :nationality_gate, []

      # `->(env) { solid_or_nil }` — the uid your app holds for the person signed in to it. Set it on a
      # provider that asks vits.me about that person (verify a name, an age, a nationality): the
      # answer must be theirs. vits.me is told whom to expect, and the callback refuses anyone else.
      option :expected_uid, nil
      # Refuse a pending (fluid_) identity. nil = on whenever expected_uid is set.
      option :require_verified, nil
      # Tell vits.me whom you expect (OIDC `claims` sub value) so it pre-selects that person and refuses
      # others. The callback checks either way.
      option :send_expected_uid, true

      FAILURES = %i[identity_mismatch not_signed_in unverified_identity nationality_gate_refused site_suspended].freeze

      def initialize(app, *args, &)
        super
        normalize_options!
      end

      def uid
        user_info.raw_attributes[:sub] || user_info.raw_attributes['sub'] || user_info.sub
      end

      # Methods, not the `info { }` DSL: OmniAuth merges a DSL block with every ancestor's, and the base
      # OpenID Connect strategy's would add email, first_name, nickname… — fields vits.me never sends.
      def info
        OmniAuth::Vitsme::AuthShape.info(uid, raw_info)
      end

      def extra
        OmniAuth::Vitsme::AuthShape.extra(uid, raw_info, knot: knot)
      end

      # The KNOT sources in UserInfo, fetched and verified now: their introductions live 30 seconds.
      def knot
        return @knot if defined?(@knot)

        @knot = (if raw_info['_claim_sources']
                   OmniAuth::Vitsme::Knot.resolve(raw_info,
                                                  client_id: client_options.identifier)
                 end)
      end

      # vits.me issues no refresh token and its access token lapses five seconds after issue: everything
      # it can tell you is already in `info` and `extra`.
      def credentials
        { id_token: access_token.id_token, scope: access_token.scope }
      end

      def raw_info
        @raw_info ||= user_info.raw_attributes.to_h.transform_keys(&:to_s)
      end

      def request_phase
        return fail!(:not_signed_in) if options.expected_uid && expected_uid.empty?

        super
      end

      def authorize_uri
        uri = super
        return uri unless options.expected_uid && options.send_expected_uid && !expected_uid.empty?

        with_query(uri, 'claims' => { id_token: { sub: { value: expected_uid } } }.to_json)
      end

      def callback_phase
        if params['error'] && (failure = OmniAuth::Vitsme::Catalog.failure_for(params['vitsme_error']))
          return fail!(failure, CallbackError.new(error: params['error'], reason: params['error_description']))
        end

        super
      end

      # The identity checks run here, after the auth hash is built and before your app sees it.
      def call_app!(env = @env)
        return super unless on_callback_path? && env['omniauth.auth']

        auth = env['omniauth.auth']
        return fail!(:unverified_identity) if require_verified? && auth.dig('extra', 'identity').to_s == 'fluid'
        return super unless options.expected_uid
        return fail!(:not_signed_in) if expected_uid.empty?
        return fail!(:identity_mismatch) unless Array(auth.dig('extra', 'lookup_uids')).include?(expected_uid)

        super
      end

      private

      def require_verified?
        options.require_verified.nil? ? !options.expected_uid.nil? : options.require_verified
      end

      def expected_uid
        @expected_uid ||= options.expected_uid.call(env).to_s
      end

      def normalize_options!
        options.issuer ||= OmniAuth::Vitsme.issuer(options.environment)
        scopes = (Array(options.scope).map(&:to_s) | ['openid']) +
                 Array(options.nationality_gate).map { |code| "openid_nationality__#{code.to_s.downcase}" }
        validate_scopes!(scopes)
        options.scope = scopes.uniq.map(&:to_sym)
      end

      def validate_scopes!(scopes)
        unknown = scopes.reject { |s| OmniAuth::Vitsme::Catalog.known_scope?(s) }
        unless unknown.empty?
          raise ArgumentError, "omniauth-vitsme: unknown scope(s) #{unknown.join(', ')}. " \
                               "Known: #{OmniAuth::Vitsme::Catalog.scopes.join(', ')}, openid_nationality__<cc>."
        end
        return unless scopes.include?('fluid') && scopes.any? { |s| OmniAuth::Vitsme::Catalog.gate_scope?(s) }

        raise ArgumentError, 'omniauth-vitsme: a nationality gate admits verified people only; ' \
                             'vits.me refuses it together with the fluid scope.'
      end

      def client_options
        opts = options.client_options
        issuer = URI(options.issuer)
        opts.scheme ||= issuer.scheme
        opts.host ||= issuer.host
        opts.port ||= issuer.port
        opts.identifier ||= options.client_id if options.client_id
        opts.secret ||= options.client_secret if options.client_secret
        opts
      end

      # The base strategy needs client_options.redirect_uri spelled out; default it to this provider's
      # callback on the current host (without the callback's own code/state query).
      def redirect_uri
        return super if client_options.redirect_uri

        full_host + callback_path
      end

      def with_query(uri, extra)
        parsed = URI(uri)
        parsed.query = URI.encode_www_form(URI.decode_www_form(parsed.query.to_s) + extra.to_a)
        parsed.to_s
      end
    end
  end
end
