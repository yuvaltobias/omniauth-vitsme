# frozen_string_literal: true

require 'json'
require 'uri'
require 'omniauth_openid_connect'
require 'omniauth/vitsme/issuers'
require 'omniauth/vitsme/catalog'
require 'omniauth/vitsme/auth_shape'
require 'omniauth/vitsme/http'
require 'omniauth/vitsme/subject'
require 'omniauth/vitsme/pushed_request'
require 'omniauth/vitsme/options'

module OmniAuth
  module Strategies
    # Sign in with vits.me, or ask vits.me about someone already signed in to your app.
    #
    # A sign-in names nobody and asks only who the person is: `openid`, and a gate. An ask names the person
    # already signed in to your app (`ask_about:`) and may ask for details. vits.me refuses a request for
    # details that names nobody (`:subject_required`), and so does this strategy, at boot.
    #
    #   provider :vitsme, client_id: ..., client_secret: ...                    # a sign-in
    #   provider :vitsme, name: :verify, client_id: ..., client_secret: ...,    # an ask
    #            scope: %i[age__over_18],           # checked against data/claims.json at boot
    #            ask_about: ->(env) { ... },        # the ID token (or uid) you keep for the signed-in person
    #            require_verified: true             # refuse pending (fluid_) identities: on for an ask
    #   nationality_gate: %w[IL]                    # on either: only verified IL nationals get through
    #
    # An ask is pushed to vits.me first (RFC 9126), so the browser carries only `client_id` and a `request_uri`.
    # A partner of vits.me (a KNOT) is asked with the vitsme_partner strategy, and several sources under one
    # pincode with vitsme_trip.
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

      # `->(env) { id_token_or_uid_or_nil }`: what makes this provider an ask. Return the vits.me ID token you
      # kept for the person signed in to your app (`auth.credentials.id_token`), or the uid you store for them.
      # vits.me is told whom the ask is about (the OIDC `claims` sub value; OmniAuth::Vitsme::Subject), offers
      # only that person and refuses anyone else, and so does the callback.
      option :ask_about, nil
      # Refuse a pending (fluid_) identity. nil = on for an ask.
      option :require_verified, nil

      FAILURES = %i[identity_mismatch not_signed_in unverified_identity nationality_gate_refused site_suspended
                    subject_required subject_invalid vitsme_refused vitsme_unavailable].freeze

      # Options that were renamed or went: naming one raises at boot, saying what to use instead.
      RENAMED = {
        'expected_uid' => 'ask_about: (return the vits.me ID token, or the uid, you keep for the signed-in person)',
        'send_expected_uid' => 'gone: vits.me is always told whom an ask is about'
      }.freeze

      def initialize(app, *args, &)
        super
        OmniAuth::Vitsme::Options.refuse_renamed!(options, self.class::RENAMED)
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
        OmniAuth::Vitsme::AuthShape.extra(uid, raw_info)
      end

      # vits.me issues no refresh token and its access token lapses five seconds after issue: everything
      # it can tell you is already in `info` and `extra`. Keep the ID token: your asks are about it
      # (`ask_about:`), and a partner is given it, sealed.
      def credentials
        { id_token: access_token.id_token, scope: access_token.scope }
      end

      def raw_info
        @raw_info ||= user_info.raw_attributes.to_h.transform_keys(&:to_s)
      end

      def request_phase
        return fail!(:not_signed_in) if ask? && ask_subject.empty?

        super
      rescue OmniAuth::Vitsme::PushedRequest::Refused => e
        fail!(OmniAuth::Vitsme::Catalog.failure_for(e.reason) || :vitsme_refused, e)
      rescue OmniAuth::Vitsme::HTTP::Unavailable => e
        fail!(:vitsme_unavailable, e)
      end

      # A sign-in goes in the address, as OpenID Connect has it. An ask names its subject and is pushed to
      # vits.me first, so the address carries only `client_id` and the `request_uri` vits.me answers with.
      def authorize_uri
        uri = super
        return uri unless ask?

        claims = { id_token: { sub: { value: ask_subject } } }.to_json
        parameters = URI.decode_www_form(URI(uri).query.to_s).to_h.merge('claims' => claims).merge(push_extras)
        OmniAuth::Vitsme::PushedRequest.push!(endpoint: pushed_request_endpoint,
                                              authorization_endpoint: uri.split('?').first,
                                              parameters: parameters, client_id: client_options.identifier,
                                              client_secret: client_options.secret)
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

        refusal = identity_refusal(env['omniauth.auth'])
        return fail!(refusal) if refusal

        answered(env)
      end

      private

      # The answer passed every check, and your app has it. VitsmeTrip goes on to its partners from here.
      def answered(env) = pass_to_app(env)

      def pass_to_app(env) = OmniAuth::Strategy.instance_method(:call_app!).bind_call(self, env)

      def identity_refusal(auth)
        return :unverified_identity if require_verified? && auth.dig('extra', 'identity').to_s == 'fluid'
        return unless ask?
        return :not_signed_in if ask_subject.empty?

        :identity_mismatch unless Array(auth.dig('extra', 'lookup_uids')).include?(ask_subject)
      end

      # More pushed parameters (VitsmeTrip: its stops).
      def push_extras = {}

      def ask? = !options.ask_about.nil?

      # The uid the ask is about: what `ask_about:` returns, or the `sub` of the ID token it returns.
      def ask_subject
        @ask_subject ||= OmniAuth::Vitsme::Subject.uid(ask_about_value)
      end

      def ask_about_value
        @ask_about_value ||= options.ask_about.call(env).to_s
      end

      def pushed_request_endpoint
        raw = config.raw if options.discovery && config.respond_to?(:raw)
        listed = raw && (raw['pushed_authorization_request_endpoint'] || raw[:pushed_authorization_request_endpoint])
        listed || "#{options.issuer}/oauth/par"
      end

      def require_verified?
        options.require_verified.nil? ? ask? : options.require_verified
      end

      def normalize_options!
        options.issuer ||= OmniAuth::Vitsme.issuer(options.environment)
        scopes = (Array(options.scope).map(&:to_s) | ['openid']) +
                 Array(options.nationality_gate).map { |code| "openid_nationality__#{code.to_s.downcase}" }
        validate_scopes!(scopes)
        OmniAuth::Vitsme::Options.require_subject!(scopes, ask: ask?)
        OmniAuth::Vitsme::Options.warn_deprecated(scopes)
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
    end
  end
end
