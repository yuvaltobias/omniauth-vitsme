# frozen_string_literal: true

module OmniAuth
  module Vitsme
    # Which label your site would like for an item under a scope, told to a partner with the pushed request as
    # `label_hint`: space-separated "scope:label" pairs (`label_hint=email:work phone:mobile`). A partner whose items
    # carry labels may use it to sort or preselect the person's item with that label on its consent page; it never
    # tells the label back, and a partner without labels ignores it.
    #
    # Given as a Hash { scope => label }, string or symbol keys and values. Labels differ by partner, so only the
    # shape is checked here: a scope and a label, each a token with no whitespace or colon. At boot a malformed
    # hint raises; at request time anything malformed, or under a scope the request does not ask, is dropped.
    module LabelHint
      TOKEN = /\A[^\s:]+\z/

      module_function

      # The well-formed pairs under a scope asked, as strings, in the order given.
      def pairs(hint, scope)
        return {} unless hint.is_a?(Hash)

        asked = Array(scope).map(&:to_s)
        hint.to_h { |key, label| [key.to_s, label.to_s] }
            .select { |key, label| asked.include?(key) && TOKEN.match?(key) && TOKEN.match?(label) }
      end

      # The `label_hint` parameter, or nil when no pair is left.
      def param(hint, scope)
        pairs = pairs(hint, scope)
        pairs.empty? ? nil : pairs.map { |key, label| "#{key}:#{label}" }.join(' ')
      end

      # The boot check for a hint configured as it is (not worked out at the click): raises unless every pair is
      # well formed and under a scope asked.
      def check!(hint, scope, where)
        problem = problem(hint, scope) unless hint.nil?
        raise ArgumentError, "omniauth-vitsme: #{where} label_hint: #{problem}" if problem
      end

      def problem(hint, scope)
        return 'is a Hash { scope => label }' unless hint.is_a?(Hash)

        hint = hint.to_h { |key, label| [key.to_s, label.to_s] }
        malformed = hint.reject { |key, label| TOKEN.match?(key) && TOKEN.match?(label) }
        unless malformed.empty?
          return "#{malformed.map { |pair| pair.join(':').inspect }.join(', ')} is not a scope and a label, " \
                 'each without spaces or colons'
        end

        unasked = hint.keys - Array(scope).map(&:to_s)
        "names #{unasked.join(', ')}, a scope it does not ask" unless unasked.empty?
      end
    end
  end
end
