# frozen_string_literal: true

require 'json/jwt'
require 'omniauth/vitsme/http'

module OmniAuth
  module Vitsme
    # Published signing keys (a JWKS URL's JSON::JWK::Set), cached per URL for TTL seconds and fetched again
    # once when a token names a key the cache does not hold (rotation).
    module Keys
      TTL = 600

      class Unavailable < StandardError; end

      @cache = {}
      @mutex = Mutex.new

      class << self
        def for(jwks_uri, kid:)
          set = cached(jwks_uri)
          return set if kid.nil? || set.any? { |jwk| jwk[:kid] == kid }

          fetch(jwks_uri)
        end

        def clear!
          @mutex.synchronize { @cache.clear }
        end

        private

        def cached(jwks_uri)
          entry = @mutex.synchronize { @cache[jwks_uri] }
          return entry[:set] if entry && entry[:at] > Time.now - TTL

          fetch(jwks_uri)
        end

        def fetch(jwks_uri)
          response = HTTP.get(jwks_uri, 'Accept' => 'application/json')
          raise Unavailable, "keys: HTTP #{response.status}" unless response.ok?

          set = JSON::JWK::Set.new(response.json)
          @mutex.synchronize { @cache[jwks_uri] = { set: set, at: Time.now } }
          set
        rescue JSON::ParserError, HTTP::Unavailable => e
          raise Unavailable, "keys: #{e.message}"
        end
      end
    end
  end
end
