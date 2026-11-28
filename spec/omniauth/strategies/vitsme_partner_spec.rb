# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::VitsmePartner do
  include Rack::Test::Methods

  let(:provider_options) { {} }
  let(:id_token) { 'the.id.token' }

  # Rack::Test builds the app once, so the ID token is read through the example at each request.
  def app
    example = self
    options = { name: :acme, partner: PartnerStub::ISSUER, scope: %w[email], client_id: VitsMeStub::CLIENT_ID,
                client_secret: VitsMeStub::CLIENT_SECRET, issuer: VitsMeStub::ISSUER,
                ask_about: ->(_env) { example.id_token } }.merge(provider_options)
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'x' * 64
      use OmniAuth::Builder do
        provider :vitsme_partner, options
      end
      run ->(env) { [200, { 'content-type' => 'application/json' }, [env['omniauth.auth'].to_hash.to_json]] }
    end
  end

  before do
    OmniAuth::Vitsme::Partner.clear!
    OmniAuth::Vitsme::Keys.clear!
    PartnerStub.stub_vitsme
  end

  # The last pushed request: a second sign-in in one example pushes again.
  def pushed
    WebMock::RequestRegistry.instance.requested_signatures.hash.keys.select { |sig| sig.uri.path == '/knot/par' }.last
  end

  def pushed_params = Rack::Utils.parse_query(pushed.body)

  it 'pushes the request with PKCE and sends the person to the partner' do
    PartnerStub.stub_partner
    get '/auth/acme'
    expect(Rack::Utils.parse_query(URI(last_response.location).query))
      .to eq('client_id' => VitsMeStub::CLIENT_ID, 'request_uri' => 'urn:ietf:params:oauth:request_uri:sealed')
    expect(pushed_params).to include('client_id' => VitsMeStub::CLIENT_ID, 'scope' => 'email',
                                     'code_challenge_method' => 'S256',
                                     'redirect_uri' => 'http://example.org/auth/acme/callback')
  end

  it 'sends the ID token sealed: as id_token_hint, encrypted so only vits.me can read it' do
    PartnerStub.stub_partner
    get '/auth/acme'
    sealed = pushed_params.fetch('id_token_hint')
    expect(sealed).not_to include(id_token)
    expect(JSON::JWT.decode(sealed, PartnerStub::VITSME_ENC).plain_text).to eq(id_token)
  end

  it 'refuses id_token: at boot, naming ask_about:' do
    strategy = lambda do
      described_class.new(->(_env) { [200, {}, []] }, partner: PartnerStub::ISSUER, id_token: ->(_env) {})
    end
    expect { strategy.call }.to raise_error(ArgumentError, /id_token: is now ask_about:/)
  end

  it "redeems the code and hands over the verified answer, under the partner's identifier for the person" do
    PartnerStub.stub_partner(refresh_token: 'refresh-1')
    get '/auth/acme'
    get '/auth/acme/callback', code: 'the-code', state: pushed_params.fetch('state'), iss: PartnerStub::ISSUER
    auth = JSON.parse(last_response.body)
    expect(auth).to include('uid' => PartnerStub::SUBJECT, 'credentials' => { 'refresh_token' => 'refresh-1' })
    expect(auth['extra']).to include('partner' => PartnerStub::ISSUER, 'claims' => { 'email' => PartnerStub::EMAILS })
    expect(WebMock).to have_requested(:post, "#{PartnerStub::ISSUER}/knot/token")
      .with(body: hash_including('grant_type' => 'authorization_code', 'code_verifier' => /\A[\w-]{64}\z/))
  end

  it 'shows a software statement with each request to a partner that takes no registrations' do
    PartnerStub.stub_partner(statement_required: true)
    statement = WebMock.stub_request(:post, "#{VitsMeStub::ISSUER}/oauth/software_statement")
                       .with(body: { 'audience' => PartnerStub::ISSUER })
                       .to_return(headers: { 'Content-Type' => 'application/json' },
                                  body: { software_statement: 'signed.statement' }.to_json)
    get '/auth/acme'
    expect(statement).to have_been_requested
    expect(pushed_params).to include('software_statement' => 'signed.statement')
  end

  context 'with the secret the partner gave at registration' do
    let(:provider_options) { { partner_secret: 'partner-secret' } }

    it 'authenticates with it' do
      PartnerStub.stub_partner
      get '/auth/acme'
      basic = Base64.strict_encode64("#{VitsMeStub::CLIENT_ID}:partner-secret")
      expect(pushed.headers['Authorization']).to eq("Basic #{basic}")
    end
  end

  it 'asks no partner vits.me does not list as active' do
    PartnerStub.stub_vitsme(status: 'suspended')
    PartnerStub.stub_partner
    get '/auth/acme'
    expect(last_response.body).to eq('partner_untrusted')
  end

  context 'without an ID token for the person' do
    let(:id_token) { '' }

    it 'asks nobody' do
      PartnerStub.stub_partner
      get '/auth/acme'
      expect(last_response.body).to eq('not_signed_in')
    end
  end

  it "refuses a callback whose state is not this request's, or from another issuer" do
    PartnerStub.stub_partner
    get '/auth/acme'
    get '/auth/acme/callback', code: 'c', state: 'forged'
    expect(last_response.body).to eq('csrf_detected')

    get '/auth/acme'
    get '/auth/acme/callback', code: 'c', state: pushed_params.fetch('state'), iss: 'https://evil.test'
    expect(last_response.body).to eq('partner_mixup')
  end

  it 'says the person was not asked when the partner says so' do
    PartnerStub.stub_partner
    get '/auth/acme'
    get '/auth/acme/callback', error: 'access_denied', state: pushed_params.fetch('state')
    expect(last_response.body).to eq('access_denied')
  end

  it 'pushes no label hint, and refuses one at boot, naming the scope to ask instead' do
    PartnerStub.stub_partner
    get '/auth/acme'
    expect(pushed_params).not_to have_key('label_hint')
    expect do
      described_class.new(lambda { |_env|
        [200, {}, []]
      }, partner: PartnerStub::ISSUER, scope: %w[email], label_hint: { email: :work })
    end.to raise_error(ArgumentError, /label_hint: is now a scope for the label instead, such as email__work/)
  end

  context 'with a required scope' do
    let(:provider_options) { { scope: %w[email* phone] } }

    it 'pushes the star' do
      PartnerStub.stub_partner
      get '/auth/acme'
      expect(pushed_params).to include('scope' => 'email* phone')
    end

    it 'hands over an answer that carries it' do
      PartnerStub.stub_partner
      get '/auth/acme'
      get '/auth/acme/callback', code: 'the-code', state: pushed_params.fetch('state'), iss: PartnerStub::ISSUER
      expect(JSON.parse(last_response.body).dig('extra', 'claims', 'email')).to eq(PartnerStub::EMAILS)
    end

    it 'fails :required_missing for an answer without it' do
      PartnerStub.stub_partner(claims: { 'email' => [], 'phone' => [{ 'number' => '+972501234567' }] })
      get '/auth/acme'
      get '/auth/acme/callback', code: 'the-code', state: pushed_params.fetch('state'), iss: PartnerStub::ISSUER
      expect(last_response.body).to eq('required_missing')
    end
  end

  it 'refuses a star on nothing at boot' do
    expect { described_class.new(->(_env) { [200, {}, []] }, partner: PartnerStub::ISSUER, scope: %w[*]) }
      .to raise_error(ArgumentError, /only a detail can be required/)
  end
end
