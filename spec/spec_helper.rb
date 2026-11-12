# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
  add_filter '/examples/'
  minimum_coverage 90
end

require 'logger'
require 'omniauth-vitsme'
require 'omniauth/vitsme/test'
require 'rack/session'
require 'rack/test'
require 'webmock/rspec'
require_relative 'support/vits_me_stub'
require_relative 'support/partner_stub'

WebMock.disable_net_connect!

OmniAuth.config.logger = Logger.new(nil)
OmniAuth.config.allowed_request_methods = %i[get post]
OmniAuth.config.request_validation_phase = nil
OmniAuth.config.on_failure = lambda do |env|
  [401, { 'content-type' => 'text/plain' }, [env['omniauth.error.type'].to_s]]
end

RSpec.configure do |config|
  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.order = :random
  config.before { OmniAuth::Vitsme::Keys.clear! }
  Kernel.srand config.seed
end
