# frozen_string_literal: true

require 'omniauth/vitsme/catalog'

module OmniAuth
  module Vitsme
    # Required scopes: a star after a scope your site cannot continue without, in an ask to vits.me
    # (`scope: %i[openid full_name__intl*]`) or to a partner (`scope: %w[email*]`). vits.me or the partner marks it on
    # its consent page, and its answer waits until the person gives it; the person may still cancel, and your callback
    # then fails `:access_denied` as for any cancel. Only a detail may be required: a star on `openid`, `fluid` or a
    # gate raises at boot. Your registration lists the plain names, and everything that comes back (claims, the token's
    # scope) carries plain names too.
    #
    # The gem checks the answer as well: a required scope that came back without its claim fails `:required_missing`
    # (for a trip's stop, that stop's `error`), so a server that left a starred scope out cannot hand you an answer you
    # said you cannot use.
    module Required
      STAR = '*'

      module_function

      def plain(scope) = scope.to_s.delete_suffix(STAR)

      # Every scope, by its plain name.
      def plain_all(scopes) = Array(scopes).map { |scope| plain(scope) }

      # The plain names of the scopes marked required.
      def names(scopes)
        Array(scopes).map(&:to_s).select { |scope| scope.end_with?(STAR) }.map { |scope| plain(scope) }.uniq
      end

      # Raises for a star on nothing, and, asking vits.me (`identity: true`), for a star on what is not a detail.
      def check!(scopes, where, identity: false)
        misplaced = names(scopes).select { |scope| scope.empty? || (identity && Catalog.identity_scope?(scope)) }
        return if misplaced.empty?

        starred = misplaced.map { |scope| "#{scope}#{STAR}" }.join(', ')
        raise ArgumentError, "omniauth-vitsme: #{where} requires #{starred}; " \
                             'only a detail can be required (openid, fluid and gates cannot)'
      end

      # vits.me's answer: the required scopes none of whose claims came back (a false is an answer; absent is not).
      def missing_at_vitsme(scopes, claims)
        claims = claims.to_h.transform_keys(&:to_s)
        names(scopes).reject do |scope|
          Catalog.claims.any? { |name, claim| claim['scope'] == scope && present?(claims[name]) }
        end
      end

      # A partner's answer, { scope => [...] }, with an empty list for a scope not given.
      def missing_at_partner(scopes, claims)
        claims = claims.to_h.transform_keys(&:to_s)
        names(scopes).reject { |scope| Array(claims[scope]).any? }
      end

      def present?(value) = !(value.nil? || value == '' || value == [])
    end
  end
end
