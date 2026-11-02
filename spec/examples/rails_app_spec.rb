# frozen_string_literal: true

ENV['VITSME_CLIENT_ID'] = VitsMeStub::CLIENT_ID
ENV['VITSME_CLIENT_SECRET'] = VitsMeStub::CLIENT_SECRET
require_relative '../../examples/rails/app'
ExampleApp.initialize! unless ExampleApp.initialized?

# Boots examples/rails/app.rb and drives the real strategy against a stubbed vits.me, end to end
# through Rails' session and routing.
RSpec.describe 'examples/rails/app.rb' do # rubocop:disable RSpec/DescribeClass
  include Rack::Test::Methods

  let(:app) { ExampleApp }
  let(:person) { OmniAuth::Vitsme::Test.uid }

  around do |example|
    rails_failure = proc { |env| OmniAuth::FailureEndpoint.new(env).redirect_to_failure }
    original = OmniAuth.config.on_failure
    OmniAuth.config.on_failure = rails_failure
    example.run
  ensure
    OmniAuth.config.on_failure = original
  end

  before { VitsMeStub.stub_discovery }

  def round_trip(provider, userinfo)
    get "https://example.test/auth/#{provider}"
    follow_redirect! while last_response.redirect? && !last_response.location.start_with?('https://vits.me')
    return last_response unless last_response.redirect?

    query = Rack::Utils.parse_query(URI(last_response.location).query)
    VitsMeStub.stub_sign_in(userinfo: userinfo, nonce: query.fetch('nonce'))
    get "https://example.test/auth/#{provider}/callback", code: 'c', state: query.fetch('state')
    follow_redirect! while last_response.redirect?
    last_response
  end

  it 'signs a verified person in' do
    expect(round_trip(:vitsme, 'sub' => person).body).to eq('signed in (verified)')
  end

  it 'verifies a detail about the person signed in' do
    round_trip(:vitsme, 'sub' => person)

    expect(round_trip(:vitsme_verify, 'sub' => person, 'age__over_18' => true).body).to eq('over 18: true')
  end

  it 'says "not shared" rather than "no" when the person keeps a detail to themselves' do
    round_trip(:vitsme, 'sub' => person)

    expect(round_trip(:vitsme_verify, 'sub' => person).body).to eq('over 18: not shared')
  end

  it 'refuses an answer about someone else' do
    round_trip(:vitsme, 'sub' => person)

    expect(round_trip(:vitsme_verify, 'sub' => OmniAuth::Vitsme::Test.uid).body).to eq('refused: identity_mismatch')
  end

  it 'refuses to verify when nobody is signed in, without a trip to vits.me' do
    expect(round_trip(:vitsme_verify, 'sub' => person).body).to eq('refused: not_signed_in')
  end

  it 'sends the gate and reports a refused one' do
    get 'https://example.test/auth/vitsme_gated'
    query = Rack::Utils.parse_query(URI(last_response.location).query)
    expect(query['scope']).to eq('openid openid_nationality__il')

    get 'https://example.test/auth/vitsme_gated/callback',
        error: 'access_denied', vitsme_error: 'nationality_gate', state: query['state']
    follow_redirect!
    expect(last_response.body).to eq('refused: nationality_gate_refused')
  end
end
