# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json/jwt'
require 'securerandom'
require 'omniauth/vitsme/http'
require 'omniauth/vitsme/jws'
require 'omniauth/vitsme/keys'
require 'omniauth/vitsme/required'
require 'omniauth/vitsme/partner_directory'

module OmniAuth
  module Vitsme
    # Asking a partner of vits.me (a KNOT) about a person signed in to your site. Partners are OAuth servers
    # of their own: your site is their client, asks them directly, and gets their answer straight from them.
    # vits.me only signs the person in there and makes sure it is the person you mean, from the sealed subject
    # you send: the ID token vits.me gave you for them, encrypted to vits.me, so the partner cannot read it.
    #
    # The browser part is the `vitsme_partner` strategy (OmniAuth::Strategies::VitsmePartner). This module
    # is the rest: whom to trust, the partner's endpoints, and asking again with a refresh token.
    module Partner
      STATEMENT_TYPE = 'software-statement+jwt'

      # The partner refused: an OAuth error, with its description.
      class Refused < StandardError; end

      Result = Struct.new(:claims, :subject, :refresh_token, :scopes, keyword_init: true)
      # A request pushed to a partner: where to send the person, and what its callback checks and redeems with.
      Asked = Struct.new(:location, :state, :verifier, keyword_init: true)

      class << self
        # Whom to trust and where its endpoints are (PartnerDirectory).
        def listing(vitsme_issuer) = PartnerDirectory.listing(vitsme_issuer)
        def trusted!(partner, vitsme_issuer) = PartnerDirectory.trusted!(partner, vitsme_issuer)
        def metadata(partner) = PartnerDirectory.metadata(partner)
        def clear! = PartnerDirectory.clear!

        # The sealed subject: the ID token you hold for the person, encrypted to vits.me's own key (use: enc in
        # its JWKS), anew each time, so the partner can neither read it nor match one person's requests. It goes
        # to the partner as `id_token_hint`, and the partner carries it to vits.me unread.
        def seal_subject(id_token, vitsme_issuer)
          key = Keys.for("#{vitsme_issuer}/oauth/discovery/keys", kid: nil).find { |jwk| jwk[:use] == 'enc' }
          raise Unavailable, 'vits.me publishes no encryption key' unless key

          jwe = JSON::JWE.new(id_token.to_s)
          jwe.alg = :'RSA-OAEP'
          jwe.enc = :A256GCM
          jwe.header[:cty] = 'JWT'
          jwe.kid = key[:kid]
          jwe.encrypt!(key.to_key)
          jwe.to_s
        end

        # What vits.me says about your site, made out to one partner, for a partner that takes no
        # registrations (it asks for one with each request) or for registering at one that does.
        def software_statement(vitsme_issuer:, client_id:, client_secret:, audience:)
          response = HTTP.post_form("#{vitsme_issuer}/oauth/software_statement", { audience: audience },
                                    basic: [client_id, client_secret], headers: { 'Accept' => 'application/json' })
          raise Refused, "vits.me: HTTP #{response.status}" unless response.ok?

          response.json.fetch('software_statement')
        end

        # Registers your site at a partner that takes registrations (RFC 7591). Returns its answer: keep
        # `client_secret`, which it shows once.
        def register(partner:, software_statement:, events_uri: nil, app_roles: nil)
          endpoint = metadata(partner)['registration_endpoint'] or raise Refused, "#{partner} takes no registrations"
          body = { software_statement: software_statement, events_uri: events_uri, app_roles: app_roles }.compact
          response = HTTP.post_json(endpoint, body)
          raise Refused, refusal(response) unless response.status == 201

          response.json
        end

        def pkce
          verifier = SecureRandom.urlsafe_base64(48)
          [verifier, Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)]
        end

        # Asks a partner about the person an ID token names: checks vits.me lists it as active, pushes the request
        # with the sealed subject (and a software statement where the partner wants one), and returns where to send
        # the person, with the state and PKCE verifier its callback needs.
        # The vitsme_partner and vitsme_trip strategies ask this way.
        def ask(partner:, scope:, id_token:, client_id:, client_secret:, redirect_uri:, vitsme_issuer:,
                partner_secret: nil, ui_locales: nil)
          trusted!(partner, vitsme_issuer)
          verifier, challenge = pkce
          state = SecureRandom.urlsafe_base64(24)
          params = { response_type: 'code', client_id: client_id, redirect_uri: redirect_uri,
                     scope: Array(scope).join(' '), state: state, code_challenge: challenge,
                     code_challenge_method: 'S256', ui_locales: ui_locales,
                     id_token_hint: seal_subject(id_token, vitsme_issuer) }.compact
          if metadata(partner)['software_statement_required']
            params[:software_statement] = software_statement(vitsme_issuer: vitsme_issuer, client_id: client_id,
                                                             client_secret: client_secret, audience: partner)
          end
          basic = partner_secret ? [client_id, partner_secret] : nil
          Asked.new(location: push(partner, params, basic: basic), state: state, verifier: verifier)
        end

        # Pushes the request (RFC 9126) and returns where to send the person.
        def push(partner, params, basic: nil)
          meta = metadata(partner)
          response = HTTP.post_form(meta.fetch('pushed_authorization_request_endpoint'), params,
                                    basic: basic, headers: { 'Accept' => 'application/json' })
          raise Refused, refusal(response) unless response.status == 201

          uri = URI(meta.fetch('authorization_endpoint'))
          uri.query = URI.encode_www_form(client_id: params[:client_id],
                                          request_uri: response.json.fetch('request_uri'))
          uri.to_s
        end

        # Redeems the code the partner sent back, and fetches what the person agreed to.
        def finish(partner:, client_id:, code:, redirect_uri:, code_verifier:, basic: nil)
          tokens = token(partner, { grant_type: 'authorization_code', code: code, redirect_uri: redirect_uri,
                                    code_verifier: code_verifier, client_id: client_id }, basic: basic)
          result(partner, client_id, tokens)
        end

        # Asks again without the person, while their standing consent at the partner holds. Returns a
        # Result with the next refresh token: the one you used is spent. Raises Refused when it does not
        # hold any more: let go of what you had.
        def fresh_claims(partner:, client_id:, partner_secret:, refresh_token:, vitsme_issuer:)
          trusted!(partner, vitsme_issuer)
          tokens = token(partner, { grant_type: 'refresh_token', refresh_token: refresh_token },
                         basic: [client_id, partner_secret])
          result(partner, client_id, tokens)
        end

        private

        def token(partner, form, basic:)
          response = HTTP.post_form(metadata(partner).fetch('token_endpoint'), form,
                                    basic: basic, headers: { 'Accept' => 'application/json' })
          raise Refused, refusal(response) unless response.ok?

          response.json
        end

        def result(partner, client_id, tokens)
          meta = metadata(partner)
          bearer = "Bearer #{tokens.fetch('access_token')}"
          response = HTTP.get(meta.fetch('claims_endpoint'), 'Authorization' => bearer, 'Accept' => 'application/jwt')
          raise Unavailable, "#{partner}: HTTP #{response.status}" unless response.ok?

          claims = JWS.verify!(response.body, jwks_uri: meta.fetch('jwks_uri'), iss: partner, aud: client_id)
          told = claims.except('iss', 'aud', 'sub', 'iat', 'exp')
          Result.new(claims: told, subject: claims.fetch('sub'), refresh_token: tokens['refresh_token'],
                     scopes: tokens['scope'].to_s.split)
        end

        def refusal(response)
          body = response.json
          [body['error'], body['error_description']].compact.join(': ')
        rescue JSON::ParserError
          "HTTP #{response.status}"
        end
      end
    end
  end
end
