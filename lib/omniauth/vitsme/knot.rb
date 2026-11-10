# frozen_string_literal: true

require 'omniauth/vitsme/http'
require 'omniauth/vitsme/jws'
require 'omniauth/vitsme/issuers'

module OmniAuth
  module Vitsme
    # Claims from KNOTs: partner services that verify what vits.me does not (organization memberships, for
    # one) and serve it to sites directly, with vits.me brokering identity and consent.
    #
    # vits.me's UserInfo names each KNOT source with an `endpoint`, an `access_token` (an introduction,
    # encrypted to the KNOT and opaque to you), and the KNOT's `iss` and `jwks_uri`. The KNOT answers with a
    # JWS, `aud` your client_id and `sub` the response's `knot_txn`. Introductions live 30 seconds and work
    # once, so the strategy fetches them while it builds the auth hash.
    module Knot
      # Partners come and go, so the gem knows none of them: any well-formed KNOT scope is accepted, and
      # vits.me refuses one your site was not granted.
      SCOPE_PATTERN = /\Aknot:[^:\s]+:\S+\z/

      class ConsentRequired < StandardError; end
      class InvalidClient < StandardError; end
      class Unavailable < StandardError; end

      # `claims` by claim name ({ "<claim>" => <answer> }); `errors` by source, for KNOTs that could not
      # be asked or whose answer did not verify. A claim missing from `claims` is unknown, never false.
      Result = Struct.new(:claims, :errors) do
        def self.empty = new({}, {})
      end

      module_function

      def scope?(scope) = SCOPE_PATTERN.match?(scope.to_s)

      # The active KNOT scopes, as vits.me describes them now (GET <issuer>/knot/scopes): each one's
      # `scope`, `knot`, `claim`, `title`, `description` and `documentation_url`. For developers and their
      # tools; signing in never depends on it. Raises Unavailable.
      def scopes(environment: :production, issuer: nil)
        response = HTTP.get("#{issuer || Vitsme.issuer(environment)}/knot/scopes", 'Accept' => 'application/json')
        raise Unavailable, "vits.me: HTTP #{response.status}" unless response.ok?

        response.json.fetch('knot_scopes')
      rescue HTTP::Unavailable, JSON::ParserError, KeyError => e
        raise Unavailable, e.message
      end

      # Fetches and verifies every KNOT source in a UserInfo (or POST /knot/introductions) response.
      def resolve(response, client_id:)
        names = response['_claim_names'] || {}
        sources = response['_claim_sources'] || {}
        txn = response['knot_txn']
        sources.each_with_object(Result.empty) do |(source, spec), result|
          answer = answer(spec, client_id: client_id, txn: txn)
          names.each { |claim, from| result.claims[claim] = answer[claim] if from == source && answer.key?(claim) }
        rescue JWS::Invalid, Keys::Unavailable, HTTP::Unavailable, Unavailable => e
          result.errors[source] = e.message
        end
      end

      # Fresh KNOT claims about someone, without them present, while they keep a standing consent with your
      # site: vits.me introduces your site to each KNOT again. `uid` is the person's uid at your site.
      # Raises ConsentRequired when nothing asked for is still agreed, InvalidClient for wrong credentials,
      # and Unavailable when vits.me cannot be reached.
      def fresh_claims(uid:, scopes:, client_id:, client_secret:, environment: :production, issuer: nil)
        issuer ||= Vitsme.issuer(environment)
        response = HTTP.post_form("#{issuer}/knot/introductions", { sub: uid, scope: Array(scopes).join(' ') },
                                  basic: [client_id, client_secret], headers: { 'Accept' => 'application/json' })
        case response.status
        when 200 then resolve(response.json, client_id: client_id)
        when 403 then raise ConsentRequired, 'the person does not let your site be told this'
        when 401 then raise InvalidClient, 'vits.me did not accept the client credentials'
        else raise Unavailable, "vits.me: HTTP #{response.status}"
        end
      rescue HTTP::Unavailable, JSON::ParserError => e
        raise Unavailable, e.message
      end

      def answer(spec, client_id:, txn:)
        response = HTTP.get(spec.fetch('endpoint'), 'Authorization' => "Bearer #{spec.fetch('access_token')}",
                                                    'Accept' => 'application/jwt')
        raise Unavailable, "HTTP #{response.status}" unless response.ok?

        claims = JWS.verify!(response.body, jwks_uri: spec.fetch('jwks_uri'), iss: spec.fetch('iss'), aud: client_id)
        raise JWS::Invalid, 'answer for another transaction' unless txn && claims['sub'] == txn

        claims
      rescue KeyError
        raise Unavailable, 'incomplete source'
      end
    end
  end
end
