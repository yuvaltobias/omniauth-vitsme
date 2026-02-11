# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  add_filter "/spec/"
  minimum_coverage 90
end

require "omniauth/vitsme"
require "webmock/rspec"

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.example_status_persistence_file_path = ".rspec_status"
  config.disable_monkey_patching!
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.order = :random
  Kernel.srand config.seed
end
