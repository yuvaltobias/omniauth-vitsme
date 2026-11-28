# frozen_string_literal: true

require 'securerandom'
require 'omniauth/strategies/vitsme'
require 'omniauth/vitsme/partner'
require 'omniauth/vitsme/required'

module OmniAuth
  module Strategies
    # A trip: one button at your site, one pincode, then a page at each source, vits.me first and then each
    # partner (KNOT) you name, and back with every answer in one auth hash.
    #
    #   provider :vitsme_trip, name: :verify_and_groups,
    #            client_id: ..., client_secret: ...,                          # your site at vits.me
    #            ask_about: ->(env) { ...the vits.me ID token you keep for the signed-in person... },
    #            scope: %i[nationality age__over_18],                         # vits.me's own; openid alone is fine
    #            stops: [{ partner: 'https://groups.mattyr.com', scope: %w[group.membership],
    #                      partner_secret: ... },
    #                    { partner: 'https://contacts.mattyr.com', scope: %w[email__work] }],  # an Array, or ->(env) { [...] }
    #            store: Rails.cache                                           # read / write(expires_in:) / delete
    #
    # Your site stays in the middle and asks each source as it would on its own. The first ask goes to vits.me,
    # pushed, naming the person and the partners you will ask next (`vitsme_stops`); vits.me's pincode page
    # names them all. Its ID token carries the trip's ticket (`vitsme_trip`). Each partner is then asked with
    # that fresh ID token, sealed, exactly as vitsme_partner asks, and vits.me lets the partner's sign-in through
    # without the pincode page when everything matches. When it does not (too late, another browser, a partner
    # that wants its own pincode), the person simply enters the pincode there: the trip still finishes.
    #
    # Each code is redeemed as it arrives, and the answers wait in `store`, never in the session, which keeps one
    # random key: a portrait alone is 200 KB. Every leg comes back to this provider's one callback,
    # /auth/<name>/callback: list it at vits.me (it is the address partners send codes to, too) and at every
    # partner that takes registrations.
    #
    # The auth hash is provider :vitsme's (uid, info, extra.claims, credentials.id_token: keep it), plus
    # `extra.stops`, one entry per stop in order: { partner, uid, claims, scopes, refresh_token } or
    # { partner, error }. A stop that fails is recorded and the trip goes on; a first ask that fails fails the
    # trip with provider :vitsme's failure types. A stop's starred scope is required there (OmniAuth::Vitsme::Required):
    # an answer without it is that stop's `error`, 'required_missing'.
    class VitsmeTrip < Vitsme
      option :name, 'vitsme_trip'
      option :stops, nil
      option :store, nil
      option :ui_locales, nil

      SESSION_KEY = 'omniauth.vitsme_trip'
      # vits.me keeps a trip open ten minutes from the pincode.
      LIFETIME = 600

      FAILURES = (Vitsme::FAILURES + %i[partner_untrusted stops_invalid trip_expired]).freeze

      def initialize(app, *args, &)
        super
        raise ArgumentError, 'omniauth-vitsme: a trip is an ask about the person signed in: set ask_about:' unless ask?
        unless %i[read write delete].all? { |verb| store.respond_to?(verb) }
          raise ArgumentError, 'omniauth-vitsme: a trip keeps its answers server-side: set store: (Rails.cache will do)'
        end
        return if options.stops.respond_to?(:call)

        stops = Array(options.stops)
        if stops.empty?
          raise ArgumentError,
                'omniauth-vitsme: a trip names its stops: set stops: [{ partner:, scope: }]'
        end

        normalize_stops(stops, strict: true)
      end

      def request_phase
        return fail!(:not_signed_in) if ask_subject.empty?

        @stops = normalize_stops(resolve_stops)
        return fail!(:partner_untrusted) if @stops.empty?

        @stops.each { |stop| OmniAuth::Vitsme::Partner.trusted!(stop['partner'], options.issuer) }
        session[SESSION_KEY] = key = SecureRandom.urlsafe_base64(24)
        save(key, 'stops' => @stops.map { |stop| stop.slice('partner', 'scope') }, 'answers' => [])
        super
      rescue OmniAuth::Vitsme::Partner::Untrusted => e
        fail!(:partner_untrusted, e)
      rescue OmniAuth::Vitsme::Partner::Unavailable, OmniAuth::Vitsme::Keys::Unavailable => e
        fail!(:vitsme_unavailable, e)
      end

      # vits.me's leg is the base strategy's; a partner's is told apart by its state.
      def callback_phase
        trip = load_trip
        leg = trip&.dig('leg')
        return super unless leg && secure_compare(request.params['state'].to_s, leg['state'].to_s)

        stop_answered(trip)
      end

      private

      def push_extras = { 'vitsme_stops' => @stops.map { |stop| stop['partner'] }.join(' ') }

      # vits.me answered, the person is who you asked about: on to the first stop. In OmniAuth test mode the
      # mock is the whole trip's answer (OmniAuth::Vitsme::Test.mock_trip).
      def answered(env)
        return super if OmniAuth.config.test_mode

        trip = load_trip or return fail!(:trip_expired)
        auth = env['omniauth.auth']
        trip.merge!('first' => auth.to_hash, 'id_token' => auth.credentials.id_token,
                    'origin' => env['omniauth.origin'], 'params' => env['omniauth.params'])
        next_stop(trip)
      end

      def next_stop(trip)
        stop = trip['stops'][trip['answers'].size]
        return finish(trip) unless stop

        asked = ask(stop, trip['id_token'])
        trip['leg'] = { 'state' => asked.state, 'verifier' => asked.verifier, 'partner' => stop['partner'] }
        save(session[SESSION_KEY], trip)
        redirect asked.location
      rescue OmniAuth::Vitsme::Partner::Untrusted, OmniAuth::Vitsme::Partner::Unavailable,
             OmniAuth::Vitsme::Partner::Refused, OmniAuth::Vitsme::Keys::Unavailable => e
        trip['answers'] << { 'partner' => stop['partner'], 'error' => stop_failure(e) }
        next_stop(trip)
      end

      def ask(stop, id_token)
        OmniAuth::Vitsme::Partner.ask(partner: stop['partner'], scope: stop['scope'], id_token: id_token,
                                      client_id: options.client_id, client_secret: options.client_secret,
                                      partner_secret: partner_secret(stop['partner']), redirect_uri: stop_redirect_uri,
                                      vitsme_issuer: options.issuer, ui_locales: ui_locales)
      end

      def stop_answered(trip)
        leg = trip.delete('leg')
        stop = trip['stops'][trip['answers'].size]
        trip['answers'] << { 'partner' => leg['partner'] }.merge(stop_answer(leg, stop))
        next_stop(trip)
      end

      def stop_answer(leg, stop)
        return { 'error' => request.params['error'].to_s } if request.params['error']
        return { 'error' => 'partner_mixup' } if request.params['iss'] && request.params['iss'] != leg['partner']

        result = redeem(leg)
        return { 'error' => 'required_missing' } if missing_required?(stop['scope'], result.claims)

        { 'uid' => result.subject, 'claims' => result.claims, 'scopes' => result.scopes,
          'refresh_token' => result.refresh_token }.compact
      rescue OmniAuth::Vitsme::Partner::Refused, OmniAuth::Vitsme::Partner::Unavailable,
             OmniAuth::Vitsme::JWS::Invalid, OmniAuth::Vitsme::Keys::Unavailable => e
        { 'error' => stop_failure(e) }
      end

      def missing_required?(scope, claims) = OmniAuth::Vitsme::Required.missing_at_partner(scope, claims).any?

      def redeem(leg)
        OmniAuth::Vitsme::Partner.finish(partner: leg['partner'], client_id: options.client_id,
                                         code: request.params['code'], redirect_uri: stop_redirect_uri,
                                         code_verifier: leg['verifier'], basic: partner_basic(leg['partner']))
      end

      def stop_failure(error)
        case error
        when OmniAuth::Vitsme::Partner::Untrusted then 'partner_untrusted'
        when OmniAuth::Vitsme::Partner::Refused then 'partner_refused'
        else 'partner_unavailable'
        end
      end

      # Every stop asked: one auth hash, and the trip forgotten.
      def finish(trip)
        store.delete(store_key(session.delete(SESSION_KEY)))
        auth = OmniAuth::AuthHash.new(trip['first'])
        auth.extra.stops = trip['answers']
        env['omniauth.auth'] = auth
        env['omniauth.origin'] = trip['origin']
        env['omniauth.params'] = trip['params'] || {}
        pass_to_app(env)
      end

      def resolve_stops
        stops = options.stops.respond_to?(:call) ? options.stops.call(env) : options.stops
        Array(stops)
      end

      # A stop names its partner and scopes. A label hint, gone in 0.9.0, raises: ask the partner's scope for the
      # label instead (`email__work`).
      def normalize_stops(stops, strict: false)
        stops.map do |stop|
          stop = stop.to_h.transform_keys(&:to_s)
          if stop['partner'].to_s.empty?
            raise ArgumentError,
                  'omniauth-vitsme: each stop names its partner: { partner:, scope: }'
          end

          partner = stop['partner'].to_s.chomp('/')
          scope = Array(stop['scope']).map(&:to_s)
          if stop.key?('label_hint')
            raise ArgumentError, "omniauth-vitsme: stop #{partner} label_hint: ask a scope for the label instead, " \
                                 'such as email__work (the label hint went in 0.9.0)'
          end

          OmniAuth::Vitsme::Required.check!(scope, "stop #{partner}") if strict
          stop.merge('partner' => partner, 'scope' => scope)
        end
      end

      # A partner's secret is never stored with the trip: it is read again from `stops:` when needed.
      def partner_secret(partner)
        normalize_stops(resolve_stops).find { |stop| stop['partner'] == partner }&.dig('partner_secret')
      end

      def partner_basic(partner)
        secret = partner_secret(partner)
        secret ? [options.client_id, secret] : nil
      end

      def load_trip
        key = session[SESSION_KEY]
        key && store.read(store_key(key))
      end

      def save(key, trip) = store.write(store_key(key), trip, expires_in: LIFETIME)

      def store_key(key) = "omniauth-vitsme:trip:#{key}"

      # The one callback every leg comes back to, as vits.me's leg has it: partners send codes only to the exact
      # address vits.me lists for your site.
      def stop_redirect_uri = client_options.redirect_uri || (full_host + callback_path)

      # Hash#store would answer `options.store`.
      def store = options[:store]

      def ui_locales
        options.ui_locales.respond_to?(:call) ? options.ui_locales.call(env) : options.ui_locales
      end

      def secure_compare(given, expected)
        !expected.empty? && given.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(given, expected)
      end
    end
  end
end
