# frozen_string_literal: true

require 'json/jwt'
require 'omniauth/vitsme/keys'

module OmniAuth
  module Vitsme
    # Verifies a signed JWT from vits.me or a KNOT: RS256 against the keys at `jwks_uri`, then the claims
    # the caller names. Raises JWS::Invalid with a short reason.
    module JWS
      LEEWAY = 30

      class Invalid < StandardError; end

      module_function

      # The verified claims, as a Hash with string keys.
      def verify!(token, jwks_uri:, iss:, aud:, typ: nil, expiring: true, now: Time.now)
        claims = signed_claims(token, jwks_uri: jwks_uri, typ: typ)
        raise Invalid, 'unexpected issuer' unless claims['iss'] == iss
        raise Invalid, 'not addressed to you' unless Array(claims['aud']).include?(aud)
        raise Invalid, 'expired' if expiring && claims['exp'].to_i + LEEWAY < now.to_i

        claims
      end

      # The payload once the signature checks out. `alg: none` and every algorithm but RS256 are refused.
      def signed_claims(token, jwks_uri:, typ:)
        header = JSON::JWT.decode(token.to_s, :skip_verification).header
        raise Invalid, 'unexpected type' if typ && header['typ'] != typ

        keys = Keys.for(jwks_uri, kid: header['kid'])
        JSON::JWT.decode(token.to_s, keys, [:RS256]).to_h.transform_keys(&:to_s)
      rescue JSON::JWT::Exception => e
        raise Invalid, e.class.name.split('::').last
      end
    end
  end
end
