# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Events do
  let(:withdrawn) { 'https://vits.me/secevent/knot/consent-withdrawn' }

  before do
    OmniAuth::Vitsme::Partner.clear!
    OmniAuth::Vitsme::Keys.clear!
    PartnerStub.stub_vitsme
    PartnerStub.stub_partner
  end

  def verify(token)
    described_class.verify!(token, partner: PartnerStub::ISSUER, client_id: VitsMeStub::CLIENT_ID,
                                   issuer: VitsMeStub::ISSUER)
  end

  it "reads a partner's claims change and withdrawal, naming the person by the partner's identifier for them" do
    expect(verify(PartnerStub.event))
      .to have_attributes(type: :claims_changed, uid: PartnerStub::SUBJECT, scopes: ['email'], id: 'event-1')
    expect(verify(PartnerStub.event(type: withdrawn))).to have_attributes(type: :consent_withdrawn)
  end

  it 'refuses an event for another site, one the partner did not sign, a stale one, or an unknown kind' do
    expect { verify(PartnerStub.event(aud: 'another-site')) }.to raise_error(described_class::Invalid, /not addressed/)
    expect { verify(PartnerStub.event(key: OpenSSL::PKey::RSA.new(2048))) }.to raise_error(described_class::Invalid)
    expect { verify(PartnerStub.event(iat: Time.now.to_i - 3600)) }.to raise_error(described_class::Invalid, /stale/)
    expect { verify(PartnerStub.event(type: 'https://example.test/other')) }
      .to raise_error(described_class::Invalid, /unsupported/)
    expect { verify(PartnerStub.event(sub_id: { format: 'iss_sub', iss: 'x', sub: 'y' })) }
      .to raise_error(described_class::Invalid, /subject/)
  end

  it 'refuses an event from a partner vits.me no longer lists as active' do
    OmniAuth::Vitsme::Partner.clear!
    PartnerStub.stub_vitsme(status: 'suspended')
    expect { verify(PartnerStub.event) }.to raise_error(described_class::Invalid, /not an active partner/)
  end
end
