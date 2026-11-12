# frozen_string_literal: true

require 'omniauth/vitsme/jws'
require 'omniauth/vitsme/issuers'
require 'omniauth/vitsme/partner'

module OmniAuth
  module Vitsme
    # Change events a partner of vits.me (a KNOT) pushes to the events address you registered with it
    # (Security Event Tokens, RFC 8417, pushed per RFC 8935): only partners that keep a standing consent
    # send them, and only about people who gave your site one.
    #
    #   :claims_changed     what the partner would tell you about them changed: ask again
    #                       (Partner.fresh_claims with the refresh token you hold)
    #   :consent_withdrawn  they stopped it, or their account ended: forget what you had, and the refresh token
    #
    # An event names the person by the partner's identifier for them at your site (the `uid` its answers
    # gave you), never says what changed, and may arrive twice. Answer 202.
    module Events
      TYPES = {
        'https://vits.me/secevent/knot/claims-changed' => :claims_changed,
        'https://vits.me/secevent/knot/consent-withdrawn' => :consent_withdrawn
      }.freeze
      CONTENT_TYPE = 'application/secevent+jwt'
      MAX_AGE = 300

      class Invalid < StandardError; end

      Event = Struct.new(:type, :uid, :scopes, :id, :issued_at, keyword_init: true)

      module_function

      # Verifies an event from `partner` (its issuer) addressed to your site, and that vits.me still lists
      # the partner as active.
      def verify!(token, partner:, client_id:, environment: :production, issuer: nil, now: Time.now)
        Partner.trusted!(partner, issuer || Vitsme.issuer(environment))
        claims = JWS.verify!(token, jwks_uri: Partner.metadata(partner).fetch('jwks_uri'), iss: partner, aud: client_id,
                                    typ: 'secevent+jwt', expiring: false, now: now)
        raise Invalid, 'stale or future event' unless (claims['iat'].to_i - now.to_i).abs <= MAX_AGE

        event(claims)
      rescue JWS::Invalid, Keys::Unavailable, Partner::Unavailable, Partner::Untrusted, KeyError => e
        raise Invalid, e.message
      end

      def event(claims)
        sub_id = claims['sub_id']
        unless sub_id.is_a?(Hash) && sub_id['format'] == 'opaque' && sub_id['id'].to_s != ''
          raise Invalid,
                'unsupported subject'
        end

        type_uri, body = Hash(claims['events']).find { |uri, _| TYPES.key?(uri) }
        raise Invalid, 'unsupported event' unless type_uri

        Event.new(type: TYPES[type_uri], uid: sub_id['id'], scopes: Hash(body)['scope'].to_s.split, id: claims['jti'],
                  issued_at: Time.at(claims['iat'].to_i))
      end
    end
  end
end
