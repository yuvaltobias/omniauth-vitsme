# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::VitsmeTrip do
  include Rack::Test::Methods

  let(:solid) { OmniAuth::Vitsme::Test.uid }
  let(:store) { TripStore.new }
  let(:stops) do
    [{ partner: PartnerStub::ISSUER, scope: %w[email] },
     { partner: PartnerStub::OTHER, scope: %w[email], partner_secret: 'beta-secret' }]
  end
  let(:provider_options) { {} }
  let(:userinfo) { { 'sub' => solid, 'solid' => solid, 'age__over_18' => true } }

  def options
    { name: :trip, client_id: VitsMeStub::CLIENT_ID, client_secret: VitsMeStub::CLIENT_SECRET,
      client_options: { redirect_uri: 'https://rp.example/auth/trip/callback' },
      ask_about: ->(env) { env['HTTP_X_SIGNED_IN'] }, scope: %i[openid age__over_18], stops: stops,
      store: store }.merge(provider_options)
  end

  def app
    provider_options = options
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'x' * 64
      use OmniAuth::Builder do
        provider :vitsme_trip, provider_options
      end
      run ->(env) { [200, { 'content-type' => 'application/json' }, [env['omniauth.auth'].to_hash.to_json]] }
    end
  end

  before do
    OmniAuth::Vitsme::Partner.clear!
    VitsMeStub.stub_discovery
    PartnerStub.stub_vitsme
    PartnerStub.stub_partner(issuer: PartnerStub::ISSUER)
    PartnerStub.stub_partner(issuer: PartnerStub::OTHER, claims: { 'email' => [{ 'address' => 'dana@beta.example' }] })
  end

  # The button: the site sends its kept ID token for the person as ask_about.
  def start!
    header 'X-Signed-In', OmniAuth::Vitsme::Test.id_token(solid)
    get '/auth/trip'
  end

  def vitsme_answers!(info = userinfo, ticket: 'the-ticket')
    pushed = VitsMeStub.pushed
    VitsMeStub.stub_sign_in(userinfo: info, nonce: pushed.fetch('nonce'), id_token_claims: { vitsme_trip: ticket })
    get '/auth/trip/callback', code: 'vitsme-code', state: pushed.fetch('state')
  end

  def partner_answers!(issuer, **params)
    get '/auth/trip/callback', { code: 'partner-code', state: PartnerStub.pushed(issuer).fetch('state'),
                                 iss: issuer }.merge(params)
  end

  def query_of(location) = Rack::Utils.parse_query(URI(location).query)

  def auth = JSON.parse(last_response.body)

  def cookie_sizes = last_response.headers['set-cookie'].to_s.split("\n").map(&:bytesize)

  it 'pushes the first ask to vits.me, naming the person and every stop, and the address carries no more' do
    start!

    expect(query_of(last_response.location))
      .to eq('client_id' => VitsMeStub::CLIENT_ID, 'request_uri' => VitsMeStub::REQUEST_URI)
    expect(VitsMeStub.pushed).to include('vitsme_stops' => "#{PartnerStub::ISSUER} #{PartnerStub::OTHER}",
                                         'scope' => 'openid age__over_18')
    expect(JSON.parse(VitsMeStub.pushed.fetch('claims')).dig('id_token', 'sub', 'value')).to eq(solid)
  end

  def basic(secret) = "Basic #{Base64.strict_encode64("#{VitsMeStub::CLIENT_ID}:#{secret}")}"

  def fresh_id_token(issuer)
    JSON::JWT.decode(PartnerStub.pushed(issuer).fetch('id_token_hint'), PartnerStub::VITSME_ENC).plain_text
  end

  it 'asks each stop in turn with the fresh ID token, sealed, the trip ticket in it' do
    start!
    vitsme_answers!
    expect(last_response.location).to start_with("#{PartnerStub::ISSUER}/knot/authorize")
    expect(OmniAuth::Vitsme::Subject.payload(fresh_id_token(PartnerStub::ISSUER)))
      .to include('vitsme_trip' => 'the-ticket', 'sub' => solid)

    partner_answers!(PartnerStub::ISSUER)
    expect(last_response.location).to start_with("#{PartnerStub::OTHER}/knot/authorize")
    expect(WebMock).to have_requested(:post, "#{PartnerStub::OTHER}/knot/par")
      .with(headers: { 'Authorization' => basic('beta-secret') })
  end

  def stop_answer(partner, emails)
    { 'partner' => partner, 'uid' => PartnerStub::SUBJECT, 'claims' => { 'email' => emails }, 'scopes' => ['email'] }
  end

  it "hands every answer over in one auth hash: vits.me's, then each stop's, and forgets the trip" do
    start!
    vitsme_answers!
    partner_answers!(PartnerStub::ISSUER)
    partner_answers!(PartnerStub::OTHER)

    expect(auth).to include('uid' => solid, 'credentials' => hash_including('id_token' => fresh_id_token(PartnerStub::OTHER)))
    expect(auth['extra']).to include('claims' => { 'age__over_18' => true }, 'stops' => [
                                       stop_answer(PartnerStub::ISSUER, PartnerStub::EMAILS),
                                       stop_answer(PartnerStub::OTHER, [{ 'address' => 'dana@beta.example' }])
                                     ])
    expect(store.entries).to be_empty
  end

  it 'records a stop that answers access_denied, and asks the next' do
    start!
    vitsme_answers!
    partner_answers!(PartnerStub::ISSUER, error: 'access_denied', code: nil)
    expect(last_response.location).to start_with("#{PartnerStub::OTHER}/knot/authorize")

    partner_answers!(PartnerStub::OTHER)
    expect(auth.dig('extra', 'stops').map { |stop| stop.slice('partner', 'error') })
      .to eq([{ 'partner' => PartnerStub::ISSUER, 'error' => 'access_denied' }, { 'partner' => PartnerStub::OTHER }])
  end

  it 'records a stop whose code it cannot redeem, and goes on' do
    PartnerStub.stub_partner(issuer: PartnerStub::OTHER, token_status: 400)
    start!
    vitsme_answers!
    partner_answers!(PartnerStub::ISSUER)
    partner_answers!(PartnerStub::OTHER)

    expect(auth.dig('extra', 'stops').last).to eq('partner' => PartnerStub::OTHER, 'error' => 'partner_refused')
  end

  it 'keeps every answer out of the session, a portrait included' do
    portrait = { 'content_type' => 'image/jpeg', 'width' => 480, 'height' => 640,
                 'content' => Base64.strict_encode64(Random.bytes(200_000)) }
    start!
    vitsme_answers!(userinfo.merge('portrait' => portrait))
    sizes = cookie_sizes
    partner_answers!(PartnerStub::ISSUER)
    sizes += cookie_sizes

    expect(sizes.max).to be < 1024
  end

  it "fails the trip with vits.me's own failure when the first ask is refused" do
    start!
    get '/auth/trip/callback', error: 'access_denied', vitsme_error: 'subject_mismatch',
                               state: VitsMeStub.pushed.fetch('state')

    expect(last_response.body).to eq('identity_mismatch')
  end

  it 'refuses an answer about someone else before asking any partner' do
    start!
    other = OmniAuth::Vitsme::Test.uid
    vitsme_answers!({ 'sub' => other, 'solid' => other })

    expect(last_response.body).to eq('identity_mismatch')
    expect(WebMock).not_to have_requested(:post, "#{PartnerStub::ISSUER}/knot/par")
  end

  it 'refuses a partner leg whose state is not the one it sent' do
    start!
    vitsme_answers!
    get '/auth/trip/callback', code: 'c', state: 'forged', iss: PartnerStub::ISSUER

    expect(last_response.body).to eq('csrf_detected')
  end

  it 'starts no trip with a stop vits.me does not list as active' do
    PartnerStub.stub_vitsme(issuers: [PartnerStub::ISSUER])
    start!

    expect(last_response.body).to eq('partner_untrusted')
    expect(WebMock).not_to have_requested(:post, 'https://vits.me/oauth/par')
  end

  it 'fails as stops_invalid when vits.me refuses the stops at the push' do
    VitsMeStub.stub_par(status: 400, body: { error: 'invalid_request', vitsme_error: 'stops_invalid' })
    start!

    expect(last_response.body).to eq('stops_invalid')
  end

  it 'asks nobody without someone signed in' do
    get '/auth/trip'

    expect(last_response.body).to eq('not_signed_in')
  end

  context 'with stops worked out at the click' do
    let(:provider_options) do
      { stops: ->(_env) { [{ partner: PartnerStub::OTHER, scope: %w[email], partner_secret: 'beta-secret' }] } }
    end

    it 'asks those, with the secret read again when it is needed' do
      start!
      expect(VitsMeStub.pushed).to include('vitsme_stops' => PartnerStub::OTHER)
      vitsme_answers!
      partner_answers!(PartnerStub::OTHER)

      expect(auth.dig('extra', 'stops').map { |stop| stop['partner'] }).to eq([PartnerStub::OTHER])
      expect(WebMock).to have_requested(:post, "#{PartnerStub::OTHER}/knot/token")
        .with(headers: { 'Authorization' => basic('beta-secret') })
    end
  end

  context 'with a label hint on each stop' do
    let(:stops) do
      [{ partner: PartnerStub::ISSUER, scope: %w[email phone], label_hint: { email: :work, phone: 'mobile' } },
       { partner: PartnerStub::OTHER, scope: %w[email], label_hint: { 'email' => 'school' } }]
    end

    it "pushes each stop's hint with that stop's request only" do
      start!
      expect(VitsMeStub.pushed).not_to have_key('label_hint')
      vitsme_answers!
      expect(PartnerStub.pushed(PartnerStub::ISSUER)).to include('label_hint' => 'email:work phone:mobile')

      partner_answers!(PartnerStub::ISSUER)
      expect(PartnerStub.pushed(PartnerStub::OTHER)).to include('label_hint' => 'email:school')
    end
  end

  context 'with a label hint worked out at the click' do
    let(:provider_options) do
      { stops: lambda { |env|
        [{ partner: PartnerStub::ISSUER, scope: %w[email] },
         { partner: PartnerStub::OTHER, scope: %w[email], partner_secret: 'beta-secret',
           label_hint: { email: env['HTTP_X_LABEL'], phone: :mobile } }]
      } }
    end

    it 'asks a later stop with the hint of the click, kept with the stop, not one worked out again' do
      header 'X-Label', 'work'
      start!
      header 'X-Label', 'home'
      vitsme_answers!
      expect(PartnerStub.pushed(PartnerStub::ISSUER)).not_to have_key('label_hint')
      partner_answers!(PartnerStub::ISSUER)

      expect(PartnerStub.pushed(PartnerStub::OTHER)).to include('label_hint' => 'email:work')
    end

    it 'drops a malformed hint at the click rather than failing the trip' do
      header 'X-Label', 'home page'
      start!
      vitsme_answers!
      partner_answers!(PartnerStub::ISSUER)

      expect(PartnerStub.pushed(PartnerStub::OTHER)).to include('scope' => 'email')
      expect(PartnerStub.pushed(PartnerStub::OTHER)).not_to have_key('label_hint')
    end
  end

  describe 'at boot' do
    def build(**overrides)
      described_class.new(->(_env) { [200, {}, []] }, options.merge(overrides))
    end

    it 'is an ask, keeps its answers in a store, and names its stops' do
      expect { build(ask_about: nil) }.to raise_error(ArgumentError, /ask_about:/)
      expect { build(store: nil) }.to raise_error(ArgumentError, /store:/)
      expect { build(stops: []) }.to raise_error(ArgumentError, /stops:/)
      expect { build(stops: [{ scope: %w[email] }]) }.to raise_error(ArgumentError, /partner/)
    end

    it "refuses a stop's malformed label hint" do
      stop = { partner: PartnerStub::ISSUER, scope: %w[email] }
      expect { build(stops: [stop.merge(label_hint: { email: 'home page' })]) }
        .to raise_error(ArgumentError, %r{stop https://acme.test label_hint: "email:home page"})
      expect { build(stops: [stop.merge(label_hint: { phone: :mobile })]) }
        .to raise_error(ArgumentError, /names phone, a scope it does not ask/)
      expect { build(stops: [stop.merge(label_hint: 'email:work')]) }.to raise_error(ArgumentError, /is a Hash/)
    end
  end

  describe 'in OmniAuth test mode' do
    around do |example|
      OmniAuth.config.test_mode = true
      example.run
    ensure
      OmniAuth.config.test_mode = false
      OmniAuth.config.mock_auth.delete(:trip)
    end

    it 'hands over the mocked trip, after the identity checks' do
      OmniAuth::Vitsme::Test.mock_trip(:trip, uid: solid, claims: { age__over_18: true },
                                              stops: [{ partner: PartnerStub::ISSUER, claims: { email: [] } },
                                                      { partner: PartnerStub::OTHER, error: 'access_denied' }])
      header 'X-Signed-In', solid
      get '/auth/trip/callback'

      expect(auth.dig('extra', 'stops')).to match(
        [hash_including('partner' => PartnerStub::ISSUER, 'claims' => { 'email' => [] }),
         { 'partner' => PartnerStub::OTHER, 'error' => 'access_denied' }]
      )
    end

    it 'refuses a mocked trip about someone else' do
      OmniAuth::Vitsme::Test.mock_trip(:trip, stops: [])
      header 'X-Signed-In', solid
      get '/auth/trip/callback'

      expect(last_response.body).to eq('identity_mismatch')
    end
  end

  context 'with a required scope at a stop' do
    let(:stops) do
      [{ partner: PartnerStub::ISSUER, scope: %w[email*], label_hint: { email: :work } },
       { partner: PartnerStub::OTHER, scope: %w[email], partner_secret: 'beta-secret' }]
    end

    before { PartnerStub.stub_partner(issuer: PartnerStub::ISSUER, claims: { 'email' => [] }) }

    it 'pushes the star to that stop, and records its answer without it as required_missing, and goes on' do
      start!
      vitsme_answers!
      expect(PartnerStub.pushed(PartnerStub::ISSUER)).to include('scope' => 'email*', 'label_hint' => 'email:work')

      partner_answers!(PartnerStub::ISSUER)
      partner_answers!(PartnerStub::OTHER)
      expect(auth.dig('extra', 'stops').map { |stop| stop.slice('partner', 'error') })
        .to eq([{ 'partner' => PartnerStub::ISSUER, 'error' => 'required_missing' },
                { 'partner' => PartnerStub::OTHER }])
    end
  end
end
