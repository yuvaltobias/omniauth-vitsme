# frozen_string_literal: true

# The smallest Rails app that uses all three ways to ask vits.me about a person. Booted by the gem's
# test suite (spec/examples/rails_app_spec.rb) against a stubbed vits.me; run it for real with
#
#   VITSME_CLIENT_ID=… VITSME_CLIENT_SECRET=… bundle exec rackup examples/rails/config.ru
#
# A real app keeps people in a database keyed by the private uid (see `bin/rails g omniauth_vitsme:install`).
require 'logger'
require 'rails'
require 'action_controller/railtie'
require 'omniauth-vitsme'

class ExampleApp < Rails::Application
  config.root = __dir__
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.secret_key_base = ENV.fetch('SECRET_KEY_BASE', 'example-only-' * 8)
  config.hosts.clear

  vitsme = {
    client_id: ENV.fetch('VITSME_CLIENT_ID', 'example-client'),
    client_secret: ENV.fetch('VITSME_CLIENT_SECRET', 'example-secret'),
    environment: ENV.fetch('VITSME_ENVIRONMENT', 'production')
  }

  config.middleware.use OmniAuth::Builder do
    # 1. Sign in: anyone verified.
    provider :vitsme, vitsme

    # 2. Sign in to a gated community: only verified Israeli nationals get through.
    provider :vitsme, vitsme.merge(name: :vitsme_gated, nationality_gate: %w[IL])

    # 3. Verify a detail about the person signed in here — and nobody else.
    provider :vitsme, vitsme.merge(
      name: :vitsme_verify,
      scope: %i[openid age__over_18],
      expected_uid: ->(env) { env['rack.session']['vitsme_uid'] }
    )
  end

  routes.append do
    get '/auth/:provider/callback', to: 'example#callback'
    get '/auth/failure', to: 'example#failure'
  end
end

class ExampleController < ActionController::Base # rubocop:disable Style/OneClassPerFile -- a one-file example app
  def callback
    auth = request.env['omniauth.auth']
    if params[:provider] == 'vitsme_verify'
      # Absent means the person chose not to share — not "under 18".
      render plain: "over 18: #{auth.extra.claims.fetch('age__over_18', 'not shared')}"
    else
      # The uid is private: keep it server-side (here, the encrypted session), never show it.
      reset_session
      session[:vitsme_uid] = auth.uid
      render plain: "signed in (#{auth.info.verified ? 'verified' : 'pending verification'})"
    end
  end

  def failure
    render plain: "refused: #{params[:message]}", status: :forbidden
  end
end
