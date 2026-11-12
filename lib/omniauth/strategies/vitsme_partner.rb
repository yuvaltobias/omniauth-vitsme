# frozen_string_literal: true

require 'omniauth'
require 'securerandom'
require 'omniauth/vitsme/issuers'
require 'omniauth/vitsme/partner'

module OmniAuth
  module Strategies
    # Ask a partner of vits.me (a KNOT) about the person signed in to your site.
    #
    #   provider :vitsme_partner, name: :contacts,
    #            partner: 'https://contacts.mattyr.com',          # its issuer, as vits.me lists it
    #            scope: %w[email],                                 # its own scope names
    #            client_id: ..., client_secret: ...,               # your site at vits.me
    #            partner_secret: ...,                              # yours at the partner, if it takes registrations
    #            id_token: ->(env) { ...the vits.me ID token you keep for the signed-in person... }
    #
    # The person is sent to the partner, signs in there with their pincode (vits.me lets only the person
    # you mean), and answers on the partner's own page. The callback has `uid`, the partner's identifier
    # for them at your site, `extra.claims`, what they agreed to (an empty list for what they did not),
    # and `credentials.refresh_token` when the partner keeps a standing consent (ask again with
    # OmniAuth::Vitsme::Partner.fresh_claims). Ask from a button of your own, when you need it.
    class VitsmePartner
      include OmniAuth::Strategy

      SESSION_KEY = 'omniauth.vitsme_partner'

      option :name, 'vitsme_partner'
      option :partner, nil
      option :scope, []
      option :client_id, nil
      option :client_secret, nil
      option :partner_secret, nil
      option :id_token, nil
      option :ui_locales, nil
      option :environment, :production
      option :issuer, nil

      FAILURES = %i[not_signed_in partner_untrusted partner_unavailable partner_refused partner_mixup
                    access_denied].freeze

      def request_phase
        id_token = options.id_token&.call(env).to_s
        return fail!(:not_signed_in) if id_token.empty?

        OmniAuth::Vitsme::Partner.trusted!(options.partner, vitsme_issuer)
        redirect OmniAuth::Vitsme::Partner.push(options.partner, push_params(id_token), basic: partner_basic)
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

      def push_params(id_token)
        verifier, challenge = OmniAuth::Vitsme::Partner.pkce
        state = SecureRandom.urlsafe_base64(24)
        session["#{SESSION_KEY}.#{name}"] = { 'state' => state, 'verifier' => verifier }
        params = { response_type: 'code', client_id: options.client_id, redirect_uri: callback_url,
                   scope: Array(options.scope).join(' '), state: state, code_challenge: challenge,
                   code_challenge_method: 'S256', ui_locales: ui_locales,
                   id_token_hint: OmniAuth::Vitsme::Partner.hint(id_token, vitsme_issuer) }.compact
        if OmniAuth::Vitsme::Partner.metadata(options.partner)['software_statement_required']
          statement = software_statement
        end
        statement ? params.merge(software_statement: statement) : params
      end

      def software_statement
        OmniAuth::Vitsme::Partner.software_statement(vitsme_issuer: vitsme_issuer, client_id: options.client_id,
                                                     client_secret: options.client_secret, audience: options.partner)
      end

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
