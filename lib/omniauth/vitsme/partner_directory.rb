# frozen_string_literal: true

require 'omniauth/vitsme/http'

module OmniAuth
  module Vitsme
    module Partner
      class Unavailable < StandardError; end
      # vits.me does not list the partner as active: ask it nothing, and trust nothing it says.
      class Untrusted < StandardError; end
    end

    # Whom to trust, and where each partner's endpoints are: vits.me's listing of partners, and each
    # partner's own authorization server metadata (RFC 8414), both cached. Partner delegates to it.
    module PartnerDirectory
      LISTING_TTL = 300
      METADATA_TTL = 3600

      @cache = {}
      @mutex = Mutex.new

      class << self
        # vits.me's listing of partners (GET /knot/partners), cached for minutes.
        def listing(vitsme_issuer)
          cached("listing #{vitsme_issuer}", LISTING_TTL) do
            response = HTTP.get("#{vitsme_issuer}/knot/partners", 'Accept' => 'application/json')
            raise Partner::Unavailable, "vits.me: HTTP #{response.status}" unless response.ok?

            response.json.fetch('partners')
          end
        end

        def trusted!(partner, vitsme_issuer)
          entry = listing(vitsme_issuer).find { |listed| listed['issuer'] == partner }
          unless entry && entry['status'] == 'active'
            raise Partner::Untrusted, "#{partner} is not an active partner of vits.me"
          end

          entry
        end

        # The partner's metadata, cached for an hour, and only if it is about the partner itself.
        def metadata(partner)
          cached("metadata #{partner}", METADATA_TTL) do
            response = HTTP.get("#{partner}/.well-known/oauth-authorization-server", 'Accept' => 'application/json')
            raise Partner::Unavailable, "#{partner}: HTTP #{response.status}" unless response.ok?

            document = response.json
            raise Partner::Unavailable, "#{partner}: metadata for another issuer" unless document['issuer'] == partner

            document
          end
        end

        def clear!
          @mutex.synchronize { @cache.clear }
        end

        private

        def cached(key, ttl)
          entry = @mutex.synchronize { @cache[key] }
          return entry[:value] if entry && entry[:at] > Time.now - ttl

          value = yield
          @mutex.synchronize { @cache[key] = { value: value, at: Time.now } }
          value
        rescue HTTP::Unavailable, JSON::ParserError, KeyError => e
          raise Partner::Unavailable, e.message
        end
      end
    end
  end
end
