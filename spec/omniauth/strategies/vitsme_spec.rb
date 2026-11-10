# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::Vitsme do
  include Rack::Test::Methods

  let(:provider_options) { {} }
  let(:solid) { OmniAuth::Vitsme::Test.uid(:solid) }
  let(:userinfo) { { 'sub' => solid, 'solid' => solid } }

  def strategy(**options)
    described_class.new(->(_env) { [200, {}, []] }, { client_id: 'x', client_secret: 'y' }.merge(options))
  end

  def app
    options = { client_id: VitsMeStub::CLIENT_ID, client_secret: VitsMeStub::CLIENT_SECRET,
                client_options: { redirect_uri: VitsMeStub::REDIRECT_URI } }.merge(provider_options)
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'x' * 64
      use OmniAuth::Builder do
        provider :vitsme, options
      end
      run ->(env) { [200, { 'content-type' => 'application/json' }, [env['omniauth.auth'].to_hash.to_json]] }
    end
  end

  # The person signed in to the relying party, as the expected_uid lambdas below read it.
  def signed_in_as(uid)
    header 'X-Signed-In', uid
  end

  def authorize_query
    Rack::Utils.parse_query(URI(last_response.location).query)
  end

  def sign_in(info = userinfo)
    get '/auth/vitsme'
    return last_response unless last_response.redirect?

    VitsMeStub.stub_sign_in(userinfo: info, nonce: authorize_query.fetch('nonce'))
    get '/auth/vitsme/callback', code: 'the-code', state: authorize_query.fetch('state')
    last_response
  end

  def auth
    JSON.parse(last_response.body)
  end

  before { VitsMeStub.stub_discovery }

  describe 'configuration' do
    it 'is named vitsme and signs in against https://vits.me by default' do
      s = strategy
      expect(s.options.name).to eq('vitsme')
      expect(s.options.issuer).to eq('https://vits.me')
    end

    it 'picks the issuer for an environment' do
      expect(strategy(environment: :staging).options.issuer).to eq('https://staging.vits.me')
      expect(strategy(environment: 'test').options.issuer).to eq('https://vitsme.localhost')
      expect { strategy(environment: :moon) }.to raise_error(ArgumentError, /unknown environment/)
    end

    it 'derives the host from the issuer' do
      s = strategy(environment: :staging)
      expect(s.send(:client_options).host).to eq('staging.vits.me')
      expect(s.send(:client_options).identifier).to eq('x')
      expect(s.send(:client_options).secret).to eq('y')
    end

    it 'asks for the pincode every time and uses PKCE' do
      expect(strategy.options.prompt).to eq(:login)
      expect(strategy.options.pkce).to be(true)
    end

    it 'always requests openid and adds a nationality gate as gate scopes' do
      s = strategy(scope: %i[age__over_18], nationality_gate: %w[IL us])
      expect(s.options.scope).to eq(%i[age__over_18 openid openid_nationality__il openid_nationality__us])
    end

    it 'refuses an unknown scope at boot' do
      expect { strategy(scope: %i[openid id_number]) }.to raise_error(ArgumentError, /unknown scope\(s\) id_number/)
    end

    it 'refuses fluid together with a nationality gate at boot' do
      expect { strategy(scope: %i[openid fluid], nationality_gate: %w[IL]) }
        .to raise_error(ArgumentError, /fluid/)
    end
  end

  describe 'request phase' do
    it 'redirects to vits.me with the scopes, prompt=login and an S256 challenge' do
      get '/auth/vitsme'

      expect(last_response.location).to start_with('https://vits.me/oauth/authorize')
      expect(authorize_query).to include('prompt' => 'login', 'scope' => 'openid', 'code_challenge_method' => 'S256')
      expect(authorize_query).not_to have_key('claims')
    end

    context 'without an explicit redirect_uri' do
      let(:provider_options) { { client_options: {} } }

      it "uses this provider's callback on the current host" do
        get 'https://rp.example/auth/vitsme'

        expect(authorize_query['redirect_uri']).to eq('https://rp.example/auth/vitsme/callback')
      end
    end

    context 'with expected_uid' do
      let(:provider_options) { { expected_uid: ->(env) { env['HTTP_X_SIGNED_IN'] } } }

      it 'tells vits.me whom it expects' do
        signed_in_as(solid)
        get '/auth/vitsme'

        expect(JSON.parse(authorize_query.fetch('claims'))).to eq('id_token' => { 'sub' => { 'value' => solid } })
      end

      it 'fails :not_signed_in before leaving the app when nobody is signed in' do
        get '/auth/vitsme'

        expect(last_response.status).to eq(401)
        expect(last_response.body).to eq('not_signed_in')
      end
    end

    context 'with send_expected_uid: false' do
      let(:provider_options) { { expected_uid: ->(env) { env['HTTP_X_SIGNED_IN'] }, send_expected_uid: false } }

      it 'keeps the expectation to itself' do
        signed_in_as(solid)
        get '/auth/vitsme'

        expect(authorize_query).not_to have_key('claims')
      end
    end
  end

  describe 'the auth hash' do
    let(:userinfo) do
      { 'sub' => solid, 'solid' => solid, 'defunct_solids' => ['solid_old'],
        'name' => 'Jane D.', 'nationality' => 'IL',
        'age__over_18' => true, 'age__over_21' => 'false', 'age__years' => 30,
        'birthday' => '1-15', 'unknown_future_claim' => 'kept raw' }
    end

    before { sign_in }

    it 'uses the sub as uid and says the person is verified' do
      expect(auth['uid']).to eq(solid)
      expect(auth['info']).to eq('name' => 'Jane D.', 'nationality' => 'IL', 'verified' => true)
    end

    it 'types every disclosure claim, including the string forms older servers sent' do
      expect(auth.dig('extra', 'claims')).to eq(
        'name' => 'Jane D.', 'nationality' => 'IL', 'age__over_18' => true, 'age__over_21' => false,
        'age__years' => 30, 'birthday' => '1-15'
      )
    end

    it 'lists the uids to look the person up by, current first' do
      expect(auth.dig('extra', 'identity')).to eq('solid')
      expect(auth.dig('extra', 'lookup_uids')).to eq([solid, 'solid_old'])
      expect(auth.dig('extra', 'fluid_uids')).to eq([])
    end

    it 'keeps the verbatim UserInfo, unknown claims included' do
      expect(auth.dig('extra', 'raw_info', 'unknown_future_claim')).to eq('kept raw')
    end

    it 'invents nothing vits.me does not send' do
      expect(auth['info'].keys).not_to include('email', 'first_name', 'last_name', 'nickname')
    end

    it 'carries no refresh token or reusable access token' do
      expect(auth['credentials'].keys).to contain_exactly('id_token', 'scope')
    end
  end

  describe 'a claim the person did not share' do
    before { sign_in('sub' => solid, 'solid' => solid) }

    it 'is absent — never false or empty' do
      expect(auth.dig('extra', 'claims')).to eq({})
      expect(auth['info'].compact).to eq('verified' => true) # OmniAuth always adds a (nil) name key
    end
  end

  describe 'a pending (fluid) identity' do
    let(:fluid) { OmniAuth::Vitsme::Test.uid(:fluid) }

    it 'signs in as unverified when no check is asked for' do
      sign_in('sub' => fluid)

      expect(auth.dig('extra', 'identity')).to eq('fluid')
      expect(auth['info']['verified']).to be(false)
    end

    context 'with require_verified: true' do
      let(:provider_options) { { require_verified: true } }

      it 'fails :unverified_identity' do
        expect(sign_in('sub' => fluid).body).to eq('unverified_identity')
      end
    end

    it 'hands over the fluids to merge once the person is verified' do
      sign_in('sub' => solid, 'solid' => solid, 'fluid' => [fluid])

      expect(auth.dig('extra', 'fluid_uids')).to eq([fluid])
    end
  end

  describe 'identity match (expected_uid)' do
    let(:provider_options) { { expected_uid: ->(env) { env['HTTP_X_SIGNED_IN'] } } }

    it 'passes the person the app expected' do
      signed_in_as(solid)

      expect(sign_in.status).to eq(200)
      expect(auth['uid']).to eq(solid)
    end

    it 'passes a person whose SOLID the app holds from before a re-key' do
      signed_in_as('solid_old')

      expect(sign_in(userinfo.merge('defunct_solids' => ['solid_old'])).status).to eq(200)
    end

    it 'fails :identity_mismatch for anyone else' do
      signed_in_as('solid_someone_else')

      expect(sign_in.body).to eq('identity_mismatch')
    end

    it 'refuses a pending identity by default' do
      signed_in_as(solid)

      expect(sign_in('sub' => 'fluid_x').body).to eq('unverified_identity')
    end

    context 'when require_verified is turned off' do
      let(:provider_options) { { expected_uid: ->(env) { env['HTTP_X_SIGNED_IN'] }, require_verified: false } }

      it 'lets a tentative account verify against its own fluid uid' do
        signed_in_as('fluid_x')

        expect(sign_in('sub' => 'fluid_x').status).to eq(200)
      end
    end
  end

  # OmniAuth's test mode skips vits.me but still calls the strategy's call_app!, so apps' tests exercise
  # the real identity checks against OmniAuth::Vitsme::Test mocks.
  describe 'in OmniAuth test mode' do
    let(:provider_options) { { expected_uid: ->(env) { env['HTTP_X_SIGNED_IN'] } } }

    around do |example|
      OmniAuth.config.test_mode = true
      example.run
    ensure
      OmniAuth.config.test_mode = false
      OmniAuth.config.mock_auth.delete(:vitsme)
    end

    it 'passes a mock of the person signed in' do
      OmniAuth::Vitsme::Test.mock_auth(uid: solid)
      signed_in_as(solid)
      get '/auth/vitsme/callback'

      expect(last_response.status).to eq(200)
    end

    it 'refuses a mock of anyone else' do
      OmniAuth::Vitsme::Test.mock_auth
      signed_in_as(solid)
      get '/auth/vitsme/callback'

      expect(last_response.body).to eq('identity_mismatch')
    end

    it 'matches a mocked earlier uid' do
      OmniAuth::Vitsme::Test.mock_auth(defunct_uids: [solid])
      signed_in_as(solid)
      get '/auth/vitsme/callback'

      expect(last_response.status).to eq(200)
    end

    it 'refuses a mocked pending identity' do
      OmniAuth::Vitsme::Test.mock_auth(identity: :fluid)
      signed_in_as(solid)
      get '/auth/vitsme/callback'

      expect(last_response.body).to eq('unverified_identity')
    end
  end

  describe 'refusals from vits.me' do
    def refused_with(**params)
      get '/auth/vitsme'
      get '/auth/vitsme/callback', { state: authorize_query.fetch('state') }.merge(params)
      last_response.body
    end

    it 'names a failed nationality gate' do
      expect(refused_with(error: 'access_denied', vitsme_error: 'nationality_gate')).to eq('nationality_gate_refused')
      expect(refused_with(error: 'access_denied', vitsme_error: 'nationality_gate_unverified'))
        .to eq('nationality_gate_refused')
    end

    it 'names a subject mismatch vits.me caught itself' do
      expect(refused_with(error: 'access_denied', vitsme_error: 'subject_mismatch')).to eq('identity_mismatch')
    end

    it 'names a site vits.me has suspended' do
      expect(refused_with(error: 'access_denied', vitsme_error: 'application_suspended')).to eq('site_suspended')
    end

    it 'passes any other denial through as OmniAuth reports it' do
      expect(refused_with(error: 'access_denied')).to eq('access_denied')
    end
  end

  it 'sends the PKCE verifier with the code' do
    get '/auth/vitsme'
    token = VitsMeStub.stub_sign_in(userinfo: userinfo, nonce: authorize_query.fetch('nonce'))
    get '/auth/vitsme/callback', code: 'the-code', state: authorize_query.fetch('state')

    expect(token.with(body: hash_including('code_verifier' => /\A\h{128}\z/))).to have_been_requested
  end

  describe 'KNOT claims' do
    let(:provider_options) { { scope: %i[openid knot:acme:widgets] } }
    let(:userinfo) { { 'sub' => solid, 'solid' => solid }.merge(KnotStub.distributed) }

    it 'accepts a KNOT scope at boot and asks vits.me for it' do
      get '/auth/vitsme'
      expect(authorize_query.fetch('scope').split).to include('knot:acme:widgets')
    end

    it 'fetches the KNOT during the callback and hands over its verified claims, not the spent sources' do
      KnotStub.stub
      sign_in
      expect(last_response).to be_ok
      expect(auth.dig('extra', 'knot_claims')).to eq('widgets' => KnotStub::WIDGETS)
      expect(auth.dig('extra', 'knot_errors')).to eq({})
      expect(auth.dig('extra', 'raw_info').keys).not_to include('_claim_sources', '_claim_names', 'knot_txn')
    end

    it 'signs the person in all the same when the KNOT cannot be asked, saying why' do
      KnotStub.stub(status: 503)
      sign_in
      expect(last_response).to be_ok
      expect(auth.dig('extra', 'knot_claims')).to eq({})
      expect(auth.dig('extra', 'knot_errors')).to eq('acme' => 'HTTP 503')
    end
  end
end
