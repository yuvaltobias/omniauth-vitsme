# frozen_string_literal: true

module OmniAuth
  module Vitsme
    ISSUERS = {
      production: 'https://vits.me',
      staging: 'https://staging.vits.me',
      development: 'https://vitsme.localhost'
    }.freeze

    # The vits.me issuer for an environment: :production, :staging or :development (a Rails.env works
    # too — "test" maps to development).
    def self.issuer(environment = :production)
      key = environment.to_s == 'test' ? :development : environment.to_s.to_sym
      ISSUERS.fetch(key) { raise ArgumentError, "omniauth-vitsme: unknown environment #{environment.inspect}" }
    end
  end
end
