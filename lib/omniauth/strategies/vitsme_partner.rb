# frozen_string_literal: true

require 'omniauth'
require 'securerandom'
require 'omniauth/vitsme/issuers'
require 'omniauth/vitsme/partner'
require 'omniauth/vitsme/options'
require 'omniauth/vitsme/required'

module OmniAuth
  module Strategies
    # Ask a partner of vits.me (a KNOT) about the person signed in to your site.
    #
    #   provider :vitsme_partner, name: :contacts,
    #            partner: 'https://contacts.mattyr.com',          # its issuer, as vits.me lists it
    #            scope: %w[email],                                 # its own scope names (email*: required)
    #            client_id: ..., client_secret: ...,               # your site at vits.me
    #            partner_secret: ...,                              # yours at the partner, if it takes registrations
    #            ask_about: ->(env) { ...the vits.me ID token you keep for the signed-in person... },
    #
    # The person is sent to the partner, signs in there with their pincode (vits.me lets only the person
    # you mean), and answers on the partner's own page. The ID token goes to the partner sealed, encrypted to
    # vits.me (Partner.seal_subject), so the partner cannot read it. The callback has `uid`, the partner's
    # identifier for them at your site, `extra.claims`, what they agreed to (an empty list for what they did
    # not), and `credentials.refresh_token` when the partner keeps a standing consent (ask again with
    # OmniAuth::Vitsme::Partner.fresh_claims). To prefer a label, ask the partner's scope for it (Contacts
    # Mattyr's `email__work`): there is no label hint since 0.9.0. A starred scope is required
    # (OmniAuth::Vitsme::Required): the partner's page waits for it, and an answer without it fails
    # `:required_missing`. Ask from a button of your own, when you need it. To ask vits.me and partners under one
    # pincode, use vitsme_trip.
    class VitsmePartner
      include OmniAuth::Strategy

      SESSION_KEY = 'omniauth.vitsme_partner'

      option :name, 'vitsme_partner'
      option :partner, nil
      option :scope, []
      option :client_id, nil
      option :client_secret, nil
      option :partner_secret, nil
      option :ask_about, nil
      option :ui_locales, nil
      option :environment, :production
      option :issuer, nil

      FAILURES = %i[not_signed_in partner_untrusted partner_unavailable partner_refused partner_mixup
                    access_denied required_missing].freeze

      RENAMED = { 'id_token' => 'ask_about: (return the vits.me ID token you keep for the signed-in person)',
                  'label_hint' => 'a scope for the label instead, such as email__work ' \
                                  '(the label hint went in 0.9.0)' }.freeze

      def initialize(app, *args, &)
        super
        OmniAuth::Vitsme::Options.refuse_renamed!(options, RENAMED)
        OmniAuth::Vitsme::Required.check!(options.scope, 'vitsme_partner')
      end

      def request_phase
        id_token = options.ask_about&.call(env).to_s
        return fail!(:not_signed_in) if id_token.empty?

        asked = ask(id_token)
        session["#{SESSION_KEY}.#{name}"] = { 'state' => asked.state, 'verifier' => asked.verifier }
        redirect asked.location
      rescue OmniAuth::Vitsme::Partner::Untrusted => e
        fail!(:partner_untrusted, e)
      rescue OmniAuth::Vitsme::Partner::Unavailable, OmniAuth::Vitsme::Keys::Unavailable => e
        fail!(:partner_unavailable, e)
      rescue OmniAuth::Vitsme::Partner::Refused => e
        fail!(:partner_refused, e)
      end

      def callback_phase
        stored = session.delete("#{SESSION_KEY}.#{name}") || {}
        refusal = callback_refusal(stored)
        return fail!(refusal) if refusal

        @result = redeem(stored)
        return fail!(:required_missing) if missing_required?(options.scope, @result.claims)

        super
      rescue OmniAuth::Vitsme::Partner::Refused => e
        fail!(:partner_refused, e)
      rescue OmniAuth::Vitsme::Partner::Unavailable, OmniAuth::Vitsme::JWS::Invalid,
             OmniAuth::Vitsme::Keys::Unavailable => e
        fail!(:partner_unavailable, e)
      end

      uid { @result.subject }

      extra { { 'partner' => options.partner, 'claims' => @result.claims, 'scopes' => @result.scopes } }

      credentials { { 'refresh_token' => @result.refresh_token }.compact }

      # Without the query OmniAuth would add: the partner sends codes only to the exact address vits.me
      # lists for your site.
      def callback_url = full_host + callback_path

      private

      def ask(id_token)
        OmniAuth::Vitsme::Partner.ask(partner: options.partner, scope: options.scope, id_token: id_token,
                                      client_id: options.client_id, client_secret: options.client_secret,
                                      partner_secret: options.partner_secret, redirect_uri: callback_url,
                                      vitsme_issuer: vitsme_issuer, ui_locales: ui_locales)
      end

      def callback_refusal(stored)
        return :csrf_detected unless stored['state'] && secure_compare(request.params['state'].to_s,
                                                                       stored['state'])
        return :access_denied if request.params['error']

        :partner_mixup if request.params['iss'] && request.params['iss'] != options.partner
      end

      def redeem(stored)
        OmniAuth::Vitsme::Partner.finish(partner: options.partner, client_id: options.client_id,
                                         code: request.params['code'], redirect_uri: callback_url,
                                         code_verifier: stored['verifier'], basic: partner_basic)
      end

      def missing_required?(scope, claims) = OmniAuth::Vitsme::Required.missing_at_partner(scope, claims).any?

      def ui_locales
        options.ui_locales.respond_to?(:call) ? options.ui_locales.call(env) : options.ui_locales
      end

      def partner_basic = options.partner_secret ? [options.client_id, options.partner_secret] : nil

      def vitsme_issuer = options.issuer || OmniAuth::Vitsme.issuer(options.environment)

      def secure_compare(given, expected)
        given.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(given, expected)
      end
    end
  end
end
