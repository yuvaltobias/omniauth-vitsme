# frozen_string_literal: true

require 'omniauth/vitsme/catalog'

module OmniAuth
  module Vitsme
    # Boot checks the strategies share: options that were renamed, details asked without naming the person, and
    # deprecated scopes.
    module Options
      module_function

      # Raises for an option that was renamed or went, saying what to use instead.
      # The gate scopes `nationality_gate:` and `age_gate:` name (docs/gates.md in the vits.me repository).
      def gates(nationalities, age)
        Array(nationalities).map { |code| "openid_nationality__#{code.to_s.downcase}" } +
          Array(age).map { |years| "openid_age__over_#{years}" }
      end

      def refuse_renamed!(options, renamed)
        given = renamed.keys.select { |name| options.key?(name) }
        return if given.empty?

        raise ArgumentError, "omniauth-vitsme: #{given.map { |name| "#{name}: is now #{renamed[name]}" }.join('; ')}"
      end

      # A request for details names its person: vits.me refuses one that does not (`subject_required`).
      def require_subject!(scopes, ask:)
        details = scopes.reject { |scope| Catalog.identity_scope?(scope) }
        return if details.empty? || ask

        raise ArgumentError, "omniauth-vitsme: #{details.join(', ')} asks for details, and a request for " \
                             'details names its person: set ask_about:, and ask from a button once the person ' \
                             'is signed in. A sign-in asks only openid and gates (nationality_gate:, age_gate:).'
      end

      def warn_deprecated(scopes)
        scopes.each do |scope|
          replacements = Catalog.deprecated(scope)
          warn "omniauth-vitsme: #{scope} is deprecated; ask for #{replacements.join(' or ')} instead." if replacements
        end
      end
    end
  end
end
