# frozen_string_literal: true

module OmniAuth
  module Vitsme
    # Turns a vits.me UserInfo response into the `info` and `extra` of the auth hash. One builder for
    # the strategy and for OmniAuth::Vitsme::Test, so a mocked sign-in has exactly the real shape.
    module AuthShape
      SOLID_PREFIX = 'solid_'
      FLUID_PREFIX = 'fluid_'
      # Spent as soon as the strategy fetched them, and none of your app's business afterwards.
      KNOT_SOURCE_KEYS = %w[_claim_names _claim_sources knot_txn].freeze

      module_function

      # :solid for a verified person, :fluid for a pending signup (only with the `fluid` scope).
      def identity_kind(uid)
        uid.to_s.start_with?(FLUID_PREFIX) ? :fluid : :solid
      end

      def info(uid, raw_info)
        claims = claims(raw_info)
        {
          name: claims['name'] || claims['name__full'],
          nationality: claims['nationality'],
          verified: identity_kind(uid) == :solid
        }.compact
      end

      # `knot` is the Knot::Result for this sign-in's KNOT sources, if it had any.
      def extra(uid, raw_info, knot: nil)
        knot ||= Knot::Result.empty
        {
          identity: identity_kind(uid),
          # Look a returning person up by every one of these, current first: a record keyed by a defunct
          # SOLID belongs to this person and should move to `uid`.
          lookup_uids: [uid.to_s, *Array(raw_info['defunct_solids'])].uniq,
          # Tentative accounts (keyed by a pending signup's FLUID) to merge into this person.
          fluid_uids: Array(raw_info['fluid']),
          claims: claims(raw_info),
          # Claims from KNOTs, by claim name, already fetched and verified ({ "<claim>" => <answer> }),
          # and why a KNOT could not be asked, by source. A claim missing here is unknown, never false.
          knot_claims: knot.claims,
          knot_errors: knot.errors,
          raw_info: raw_info.except(*KNOT_SOURCE_KEYS)
        }
      end

      # The disclosure claims vits.me returned, typed by the catalog. Identity claims (sub, solid,
      # defunct_solids, fluid) are in `uid`, `lookup_uids` and `fluid_uids` instead; anything the
      # catalog does not know stays in raw_info only.
      def claims(raw_info)
        Catalog.claims.each_with_object({}) do |(name, spec), out|
          next if Catalog::DATA['identity_scopes'].key?(spec['scope'])

          value = Catalog.coerce(name, raw_info[name])
          out[name] = value unless value.nil?
        end
      end
    end
  end
end
