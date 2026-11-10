# frozen_string_literal: true

require 'json/jwt'

# A WebMock'd KNOT, a made-up partner: its published keys and its signed answers. The gem knows no partner.
module KnotStub
  ISSUER = 'https://acme.test'
  ENDPOINT = "#{ISSUER}/knot/claims".freeze
  JWKS_URI = "#{ISSUER}/knot/jwks".freeze
  KEY = OpenSSL::PKey::RSA.new(2048)
  JWK = JSON::JWK.new(KEY.public_key, kid: 'knot-key')
  # Whatever a partner answers: the gem passes it through untouched.
  WIDGETS = [{ 'id' => 'w1', 'colour' => 'teal' }].freeze

  module_function

  def source(token = 'opaque-introduction')
    { 'endpoint' => ENDPOINT, 'access_token' => token, 'iss' => ISSUER, 'jwks_uri' => JWKS_URI }
  end

  # What vits.me's UserInfo (or POST /knot/introductions) carries for one KNOT source.
  def distributed(txn: 'txn-1', token: 'opaque-introduction')
    { '_claim_names' => { 'widgets' => 'acme' }, '_claim_sources' => { 'acme' => source(token) },
      'knot_txn' => txn }
  end

  def answer(sub:, aud: VitsMeStub::CLIENT_ID, iss: ISSUER, key: KEY, claims: { 'widgets' => WIDGETS })
    now = Time.now.to_i
    jwt = JSON::JWT.new(claims.merge(iss: iss, aud: aud, sub: sub, iat: now, exp: now + 60))
    jwt.kid = 'knot-key'
    jwt.sign(key, :RS256).to_s
  end

  def stub(answer_for: 'txn-1', status: 200, **)
    WebMock.stub_request(:get, JWKS_URI).to_return(headers: { 'Content-Type' => 'application/json' },
                                                   body: { keys: [JWK.as_json] }.to_json)
    WebMock.stub_request(:get, ENDPOINT).with(headers: { 'Authorization' => 'Bearer opaque-introduction' })
           .to_return(status: status, headers: { 'Content-Type' => 'application/jwt' }, body: answer(sub: answer_for,
                                                                                                     **))
  end
end
