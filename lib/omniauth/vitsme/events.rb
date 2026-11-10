# frozen_string_literal: true

require 'omniauth/vitsme/jws'
require 'omniauth/vitsme/issuers'

module OmniAuth
  module Vitsme
    # The change events vits.me POSTs to your site's change notifications URL (Security Event Tokens,
    # RFC 8417, pushed per RFC 8935 with Content-Type application/secevent+jwt), while someone keeps a
    # standing consent with your site:
    #
    #   :claims_changed     what a KNOT would tell you about them changed: ask again (Knot.fresh_claims)
    #   :consent_withdrawn  they stopped sharing (reason "withdrawn"), or the partner or scope left
    #                       (reason "retired"): let go of what you were given
    #
    # An event never carries values. Answer 202; anything else is retried. Events are idempotent and may
    # arrive twice.
    #
    #   event = OmniAuth::Vitsme::Events.verify!(request.raw_post, client_id: ENV['VITSME_APP_ID'])
    #   person = Person.find_by(vitsme_uid: event.uid)  # the uid is private, as everywhere
    module Events
      TYPES = {
        'https://vits.me/secevent/knot/claims-changed' => :claims_changed,
        'https://vits.me/secevent/knot/consent-withdrawn' => :consent_withdrawn
      }.freeze
      CONTENT_TYPE = 'application/secevent+jwt'
      MAX_AGE = 300

      class Invalid < StandardError; end

      Event = Struct.new(:type, :uid, :scopes, :reason, :id, :issued_at, keyword_init: true)

      module_function

      def verify!(token, client_id:, environment: :production, issuer: nil, now: Time.now)
        issuer ||= Vitsme.issuer(environment)
        claims = JWS.verify!(token, jwks_uri: "#{issuer}/oauth/discovery/keys", iss: issuer, aud: client_id,
                                    typ: 'secevent+jwt', expiring: false, now: now)
        raise Invalid, 'stale or future event' unless (claims['iat'].to_i - now.to_i).abs <= MAX_AGE

        event(claims, issuer)
      rescue JWS::Invalid, Keys::Unavailable => e
        raise Invalid, e.message
      end

      def event(claims, issuer)
        sub_id = claims['sub_id']
        unless sub_id.is_a?(Hash) && sub_id['format'] == 'iss_sub' && sub_id['iss'] == issuer
          raise Invalid,
                'unsupported subject'
        end

        type_uri, body = Hash(claims['events']).find { |uri, _| TYPES.key?(uri) }
        raise Invalid, 'unsupported event' unless type_uri

        body = Hash(body)
        Event.new(type: TYPES[type_uri], uid: sub_id['sub'], scopes: body['scope'].to_s.split, reason: body['reason'],
                  id: claims['jti'], issued_at: Time.at(claims['iat'].to_i))
      end
    end
  end
end
