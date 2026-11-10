# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Events do
  let(:uid) { OmniAuth::Vitsme::Test.uid }

  before { VitsMeStub.stub_discovery }

  def token(type: 'https://vits.me/secevent/knot/claims-changed', aud: VitsMeStub::CLIENT_ID, iat: Time.now.to_i,
            key: VitsMeStub::KEY, sub_id: { format: 'iss_sub', iss: VitsMeStub::ISSUER, sub: uid }, reason: nil)
    jwt = JSON::JWT.new(iss: VitsMeStub::ISSUER, aud: aud, iat: iat, jti: 'event-1', sub_id: sub_id,
                        events: { type => { scope: 'knot:acme:widgets', reason: reason }.compact })
    jwt.kid = 'test-key'
    jwt.typ = 'secevent+jwt'
    jwt.sign(key, :RS256).to_s
  end

  def verify(event_token) = described_class.verify!(event_token, client_id: VitsMeStub::CLIENT_ID)

  it 'reads a claims change and a withdrawal, naming the person by your uid' do
    event = verify(token)
    expect(event).to have_attributes(type: :claims_changed, uid: uid, scopes: ['knot:acme:widgets'],
                                     id: 'event-1')
    retired = verify(token(type: 'https://vits.me/secevent/knot/consent-withdrawn', reason: 'retired'))
    expect(retired).to have_attributes(type: :consent_withdrawn, reason: 'retired')
  end

  it 'refuses an event for another site, one vits.me did not sign, a stale one, and an unknown kind' do
    expect { verify(token(aud: 'another-site')) }.to raise_error(described_class::Invalid, /not addressed/)
    expect { verify(token(key: OpenSSL::PKey::RSA.new(2048))) }.to raise_error(described_class::Invalid)
    expect { verify(token(iat: Time.now.to_i - 3600)) }.to raise_error(described_class::Invalid, /stale/)
    expect { verify(token(type: 'https://example.test/other')) }.to raise_error(described_class::Invalid, /unsupported/)
    expect { verify(token(sub_id: { format: 'opaque', id: 'x' })) }.to raise_error(described_class::Invalid, /subject/)
  end
end
