# frozen_string_literal: true

require 'json/jwt'

# A WebMock'd partner of vits.me (made-up ones: the gem knows no partner), and the parts of vits.me a site uses
# to ask one: its listing of partners, its encryption key for sealed subjects, and software statements. Each
# helper takes the partner's `issuer:`, Acme by default, so a trip can visit several.
module PartnerStub
  ISSUER = 'https://acme.test'
  OTHER = 'https://beta.test'
  KEY = OpenSSL::PKey::RSA.new(2048)
  JWK = JSON::JWK.new(KEY.public_key, kid: 'acme-key')
  VITSME_ENC = OpenSSL::PKey::RSA.new(2048)
  SUBJECT = 'ks_the-partners-name-for-the-person-at-your-site'
  # Whatever a partner answers: the gem passes it through untouched.
  EMAILS = [{ 'address' => 'dana@example.org' }].freeze

  module_function

  def metadata(statement_required: false, issuer: ISSUER)
    { issuer: issuer, pushed_authorization_request_endpoint: "#{issuer}/knot/par",
      authorization_endpoint: "#{issuer}/knot/authorize", token_endpoint: "#{issuer}/knot/token",
      registration_endpoint: statement_required ? nil : "#{issuer}/knot/register",
      jwks_uri: "#{issuer}/knot/jwks", claims_endpoint: "#{issuer}/knot/claims",
      software_statement_required: statement_required }.compact
  end

  # vits.me: the partners listed as `status`, and its keys with the encryption key a sealed subject is made to.
  def stub_vitsme(status: 'active', issuers: [ISSUER, OTHER])
    listed = issuers.map { |issuer| { name: issuer, slug: URI(issuer).host, issuer: issuer, status: status } }
    WebMock.stub_request(:get, "#{VitsMeStub::ISSUER}/knot/partners").to_return(
      headers: { 'Content-Type' => 'application/json' }, body: { partners: listed }.to_json
    )
    enc = JSON::JWK.new(VITSME_ENC.public_key, kid: 'vitsme-enc', use: 'enc', alg: 'RSA-OAEP')
    WebMock.stub_request(:get, "#{VitsMeStub::ISSUER}/oauth/discovery/keys").to_return(
      headers: { 'Content-Type' => 'application/json' }, body: { keys: [VitsMeStub::JWK.as_json, enc.as_json] }.to_json
    )
  end

  def stub_partner(statement_required: false, claims: { 'email' => EMAILS }, refresh_token: nil, token_status: 200,
                   issuer: ISSUER)
    json = { 'Content-Type' => 'application/json' }
    WebMock.stub_request(:get, "#{issuer}/.well-known/oauth-authorization-server")
           .to_return(headers: json, body: metadata(statement_required: statement_required, issuer: issuer).to_json)
    WebMock.stub_request(:get, "#{issuer}/knot/jwks").to_return(headers: json, body: { keys: [JWK.as_json] }.to_json)
    WebMock.stub_request(:post, "#{issuer}/knot/par").to_return(
      status: 201, headers: json, body: { request_uri: 'urn:ietf:params:oauth:request_uri:sealed',
                                          expires_in: 90 }.to_json
    )
    WebMock.stub_request(:post, "#{issuer}/knot/token")
           .to_return(status: token_status, headers: json, body: tokens(token_status, claims, refresh_token).to_json)
    WebMock.stub_request(:get, "#{issuer}/knot/claims").with(headers: { 'Authorization' => 'Bearer access-1' })
           .to_return(headers: { 'Content-Type' => 'application/jwt' }, body: answer(claims: claims, iss: issuer))
  end

  # The parameters of the last request pushed to a partner.
  def pushed(issuer = ISSUER)
    sig = WebMock::RequestRegistry.instance.requested_signatures.hash.keys
                                  .select { |s| s.uri.host == URI(issuer).host && s.uri.path == '/knot/par' }.last
    sig && Rack::Utils.parse_query(sig.body)
  end

  def tokens(status, claims, refresh_token)
    return { error: 'invalid_grant' } unless status == 200

    { access_token: 'access-1', token_type: 'Bearer', expires_in: 300, scope: claims.keys.join(' '),
      refresh_token: refresh_token }.compact
  end

  def answer(claims:, aud: VitsMeStub::CLIENT_ID, iss: ISSUER, key: KEY)
    now = Time.now.to_i
    jwt = JSON::JWT.new(claims.merge(iss: iss, aud: aud, sub: SUBJECT, iat: now, exp: now + 60))
    jwt.kid = 'acme-key'
    jwt.sign(key, :RS256).to_s
  end

  CHANGED = 'https://vits.me/secevent/knot/claims-changed'

  def event(type: CHANGED, aud: VitsMeStub::CLIENT_ID, iat: Time.now.to_i, key: KEY,
            sub_id: { format: 'opaque', id: SUBJECT })
    jwt = JSON::JWT.new(iss: ISSUER, aud: aud, iat: iat, jti: 'event-1', sub_id: sub_id,
                        events: { type => { scope: 'email' } })
    jwt.kid = 'acme-key'
    jwt.typ = 'secevent+jwt'
    jwt.sign(key, :RS256).to_s
  end
end
