# frozen_string_literal: true

require 'json'

module OmniAuth
  module Vitsme
    # The scopes, claims, gates and refusal reasons vits.me offers, read from data/claims.json — the
    # same file agents and developers read to choose scopes. The strategy validates `scope:` against it
    # at boot and types every claim value by it.
    module Catalog
      PATH = File.expand_path('../../../data/claims.json', __dir__)
      DATA = JSON.parse(File.read(PATH)).freeze
      GATE_PATTERN = Regexp.new(DATA.dig('gates', 'openid_nationality', 'scope_pattern'))

      module_function

      def claims
        DATA['claims']
      end

      def claim(name)
        claims[name.to_s]
      end

      # Every requestable scope that is not a gate.
      def scopes
        @scopes ||= (DATA['identity_scopes'].keys + claims.values.map { |c| c['scope'] }).uniq.freeze
      end

      def gate_scope?(scope)
        GATE_PATTERN.match?(scope.to_s)
      end

      def known_scope?(scope)
        scopes.include?(scope.to_s) || gate_scope?(scope)
      end

      # The OmniAuth failure type for a `vitsme_error` refusal reason, or nil for an unknown one.
      def failure_for(reason)
        DATA.dig('refusals', reason.to_s, 'omniauth_failure')&.to_sym
      end

      # A claim value as the catalog types it. Tolerates the string forms older vits.me servers sent
      # ("true", "37"); anything it cannot read as its type is dropped (nil), never guessed.
      def coerce(name, value)
        return nil if value.nil? || value == ''

        case claim(name)&.fetch('type')
        when 'boolean' then boolean(value)
        when 'integer' then integer(value)
        when 'string_array' then Array(value).map(&:to_s)
        else value.to_s
        end
      end

      def boolean(value)
        case value
        when true, 'true' then true
        when false, 'false' then false
        end
      end

      def integer(value)
        return value if value.is_a?(Integer)

        Integer(value.to_s, 10, exception: false)
      end
    end
  end
end
