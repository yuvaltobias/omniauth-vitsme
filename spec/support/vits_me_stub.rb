# frozen_string_literal: true

require 'json/jwt'

# A WebMock'd vits.me: discovery, JWKS, pushed requests, token and UserInfo endpoints, signing ID tokens
# with a throwaway RSA key. Claims are served from UserInfo only, as vits.me does (a trip's ticket apart).
module VitsMeStub
  ISSUER = 'https://vits.me'
  CLIENT_ID = 'rp-client'
  CLIENT_SECRET = 'rp-secret'
  REDIRECT_URI = 'https://rp.example/auth/vitsme/callback'
  KEY = OpenSSL::PKey::RSA.new(2048)
  JWK = JSON::JWK.new(KEY.public_key, kid: 'test-key')

  module_function

  def stub_discovery(issuer = ISSUER)
    WebMock.stub_request(:get, "#{issuer}/.well-known/openid-configuration").to_return(
      headers: { 'Content-Type' => 'application/json' },
      body: {
        issuer: issuer,
        authorization_endpoint: "#{issuer}/oauth/authorize",
        token_endpoint: "#{issuer}/oauth/token",
        userinfo_endpoint: "#{issuer}/oauth/userinfo",
        pushed_authorization_request_endpoint: "#{issuer}/oauth/par",
        jwks_uri: "#{issuer}/oauth/discovery/keys",
        response_types_supported: ['code'],
        subject_types_supported: ['pairwise'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256']
      }.to_json
    )
    WebMock.stub_request(:get, "#{issuer}/oauth/discovery/keys").to_return(
      headers: { 'Content-Type' => 'application/json' },
      body: { keys: [JWK.as_json] }.to_json
    )
    stub_par(issuer)
  end

  REQUEST_URI = 'urn:ietf:params:oauth:request_uri:from-vitsme'

  def stub_par(issuer = ISSUER, status: 201, body: { request_uri: REQUEST_URI, expires_in: 600 })
    WebMock.stub_request(:post, "#{issuer}/oauth/par")
           .to_return(status: status, headers: { 'Content-Type' => 'application/json' }, body: body.to_json)
  end

  # The parameters of the last request pushed to vits.me.
  def pushed(issuer = ISSUER)
    sig = WebMock::RequestRegistry.instance.requested_signatures.hash.keys
                                  .select { |s| s.uri.host == URI(issuer).host && s.uri.path == '/oauth/par' }.last
    sig && Rack::Utils.parse_query(sig.body)
  end

  def id_token(sub:, nonce:, issuer: ISSUER, **claims)
    now = Time.now.to_i
    jwt = JSON::JWT.new(claims.merge(iss: issuer, sub: sub, aud: CLIENT_ID, exp: now + 5, iat: now, nonce: nonce,
                                     auth_time: now))
    jwt.kid = 'test-key'
    jwt.sign(KEY, :RS256).to_s
  end

  # The token and UserInfo answers for one sign-in. Returns the token request stub for assertions.
  def stub_sign_in(userinfo:, nonce:, issuer: ISSUER, id_token_claims: {})
    token = WebMock.stub_request(:post, "#{issuer}/oauth/token").to_return(
      headers: { 'Content-Type' => 'application/json' },
      body: { access_token: 'short-lived', token_type: 'Bearer', expires_in: 5, scope: 'openid',
              id_token: id_token(sub: userinfo.fetch('sub'), nonce: nonce, issuer: issuer, **id_token_claims) }.to_json
    )
    WebMock.stub_request(:get, "#{issuer}/oauth/userinfo").to_return(
      headers: { 'Content-Type' => 'application/json' }, body: userinfo.to_json
    )
    token
  end
end
