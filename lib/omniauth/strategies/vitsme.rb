# frozen_string_literal: true

require "omniauth_openid_connect"

module OmniAuth
  module Strategies
    class Vitsme < OpenIDConnect
      option :name, "vitsme"

      option :discovery, true
      option :issuer, "https://vits.me"
      option :client_signing_alg, :RS256
      option :scope, [:openid]
      option :response_type, "code"
      option :response_mode, "query"

      option :client_options, {
        identifier: nil,
        secret: nil,
        scheme: "https",
        host: "vits.me",
        port: 443,
        authorization_endpoint: "/oauth/authorize",
        token_endpoint: "/oauth/token",
        userinfo_endpoint: "/oauth/userinfo",
        jwks_uri: "/oauth/discovery/keys"
      }

      option :client_id, nil
      option :client_secret, nil

      uid { raw_info["sub"] }

      info do
        {
          name: raw_info["name"] || raw_info["name__full"],
          first_name: raw_info["given_name"],
          last_name: raw_info["family_name"],
          email: raw_info["email"],
          birthday: raw_info["birthdate"] || raw_info["birthday"],
          nationality: raw_info["nationality"],
          age_over_13: raw_info["age__over_13"],
          age_over_18: raw_info["age__over_18"],
          age_over_21: raw_info["age__over_21"]
        }.compact
      end

      extra do
        { raw_info: raw_info }
      end

      def raw_info
        @raw_info ||= user_info.raw_attributes
      end

      private

      def client_options
        opts = options.client_options
        opts.identifier ||= options.client_id if options.client_id
        opts.secret ||= options.client_secret if options.client_secret
        opts
      end
    end
  end
end
