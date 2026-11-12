# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Partner do
  before do
    described_class.clear!
    OmniAuth::Vitsme::Keys.clear!
    PartnerStub.stub_vitsme
  end

  def fresh(refresh_token)
    described_class.fresh_claims(partner: PartnerStub::ISSUER, client_id: VitsMeStub::CLIENT_ID, partner_secret: 's',
                                 refresh_token: refresh_token, vitsme_issuer: VitsMeStub::ISSUER)
  end

  it 'asks again with a refresh token, and gets the next one' do
    PartnerStub.stub_partner(refresh_token: 'refresh-2')
    expect(fresh('refresh-1')).to have_attributes(claims: { 'email' => PartnerStub::EMAILS },
                                                  subject: PartnerStub::SUBJECT, refresh_token: 'refresh-2')
  end

  it 'says so when the consent no longer holds' do
    PartnerStub.stub_partner(token_status: 400)
    expect { fresh('spent') }.to raise_error(described_class::Refused, /invalid_grant/)
  end

  it 'trusts an answer only from the partner, addressed to you' do
    PartnerStub.stub_partner
    WebMock.stub_request(:get, "#{PartnerStub::ISSUER}/knot/claims")
           .to_return(body: PartnerStub.answer(claims: { 'email' => [] }, aud: 'another-site'))
    expect do
      described_class.finish(partner: PartnerStub::ISSUER, client_id: VitsMeStub::CLIENT_ID, code: 'c',
                             redirect_uri: 'https://rp.example/cb', code_verifier: 'v')
    end.to raise_error(OmniAuth::Vitsme::JWS::Invalid, /not addressed/)
  end

  it 'registers a site at a partner that takes registrations' do
    PartnerStub.stub_partner
    answer = { client_id: 'rp-client', client_secret: 'shown-once' }
    registration = WebMock.stub_request(:post, "#{PartnerStub::ISSUER}/knot/register")
                          .with(body: { software_statement: 'signed', app_roles: [{ key: 'editor' }] }.to_json)
                          .to_return(status: 201, headers: { 'Content-Type' => 'application/json' },
                                     body: answer.to_json)
    registered = described_class.register(partner: PartnerStub::ISSUER, software_statement: 'signed',
                                          app_roles: [{ key: 'editor' }])
    expect(registered).to include('client_secret' => 'shown-once')
    expect(registration).to have_been_requested
  end

  it 'does not trust a partner vits.me does not list as active' do
    PartnerStub.stub_vitsme(status: 'suspended')
    expect { described_class.trusted!(PartnerStub::ISSUER, VitsMeStub::ISSUER) }
      .to raise_error(described_class::Untrusted)
  end
end
