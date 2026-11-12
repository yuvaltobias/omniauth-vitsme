# frozen_string_literal: true

module OmniAuth
  module Vitsme
    # Turns a vits.me UserInfo response into the `info` and `extra` of the auth hash. One builder for
    # the strategy and for OmniAuth::Vitsme::Test, so a mocked sign-in has exactly the real shape.
    module AuthShape
      SOLID_PREFIX = 'solid_'
      FLUID_PREFIX = 'fluid_'

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

      def extra(uid, raw_info)
        {
          identity: identity_kind(uid),
          # Look a returning person up by every one of these, current first: a record keyed by a defunct
          # SOLID belongs to this person and should move to `uid`.
          lookup_uids: [uid.to_s, *Array(raw_info['defunct_solids'])].uniq,
          # Tentative accounts (keyed by a pending signup's FLUID) to merge into this person.
          fluid_uids: Array(raw_info['fluid']),
          claims: claims(raw_info),
          raw_info: raw_info
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
