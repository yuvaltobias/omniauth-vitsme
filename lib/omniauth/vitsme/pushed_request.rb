# frozen_string_literal: true

require 'json'
require 'uri'
require 'omniauth/vitsme/http'

module OmniAuth
  module Vitsme
    # An authorization request pushed to vits.me before the browser goes there (RFC 9126). Every ask is: its
    # subject, and a trip's stops, are then in no address on the way, so in no proxy log, browser history or
    # edge log. The browser carries only `client_id` and the `request_uri` vits.me answers with.
    module PushedRequest
      # vits.me refused the request: `error` is the OAuth error, `reason` its `vitsme_error`, when it gives one.
      class Refused < StandardError
        attr_reader :error, :reason

        def initialize(error, reason, description)
          @error = error
          @reason = reason
          super([error, description].compact.join(': '))
        end
      end

      module_function

      # Pushes `parameters` (the authorize request's own, string keys) and returns the address to send the
      # browser to: `authorization_endpoint` with only `client_id` and `request_uri`.
      def push!(endpoint:, authorization_endpoint:, parameters:, client_id:, client_secret:)
        response = HTTP.post_form(endpoint, parameters.except('client_secret'),
                                  basic: [client_id, client_secret], headers: { 'Accept' => 'application/json' })
        raise refusal(response) unless response.status == 201

        uri = URI(authorization_endpoint)
        uri.query = URI.encode_www_form('client_id' => client_id, 'request_uri' => response.json.fetch('request_uri'))
        uri.to_s
      end

      def refusal(response)
        body = response.json
        Refused.new(body['error'] || 'invalid_request', body['vitsme_error'], body['error_description'])
      rescue JSON::ParserError
        Refused.new('invalid_request', nil, "HTTP #{response.status}")
      end
    end
  end
end
