# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Test do
  after { OmniAuth.config.mock_auth.delete(:vitsme) }

  it 'mints private-looking uids of either kind' do
    expect(described_class.uid).to match(/\Asolid_[a-z0-9]{52}\z/)
    expect(described_class.uid(:fluid)).to start_with('fluid_')
  end

  it 'builds the same auth hash shape as the real strategy' do
    uid = described_class.uid
    auth = described_class.auth_hash(uid: uid, claims: { age__over_18: true, name: 'Jane D.' },
                                     defunct_uids: ['solid_old'])

    expect(auth.uid).to eq(uid)
    expect(auth.info.to_hash.compact).to eq('name' => 'Jane D.', 'verified' => true)
    expect(auth.extra.claims.to_hash).to eq('age__over_18' => true, 'name' => 'Jane D.')
    expect(auth.extra.lookup_uids).to eq([uid, 'solid_old'])
    expect(auth.extra.raw_info.solid).to eq(uid)
  end

  it 'builds a pending identity' do
    auth = described_class.auth_hash(identity: :fluid)

    expect(auth.extra.identity).to eq(:fluid)
    expect(auth.info.verified).to be(false)
    expect(auth.extra.raw_info).not_to have_key('solid')
  end

  it 'refuses a claim vits.me does not have' do
    expect { described_class.auth_hash(claims: { email: 'jane@example.com' }) }
      .to raise_error(ArgumentError, /unknown claim\(s\) email/)
  end

  it 'installs a mock sign-in and a mock failure' do
    described_class.mock_auth(fluid_uids: ['fluid_a'])
    expect(OmniAuth.config.mock_auth[:vitsme].extra.fluid_uids).to eq(['fluid_a'])

    described_class.mock_failure(:vitsme, :identity_mismatch)
    expect(OmniAuth.config.mock_auth[:vitsme]).to eq(:identity_mismatch)
  end

  it "mocks a partner's answer in the shape the vitsme_partner strategy gives" do
    described_class.mock_partner(:contacts, partner: PartnerStub::ISSUER, claims: { email: PartnerStub::EMAILS },
                                            refresh_token: 'r1')
    auth = OmniAuth.config.mock_auth[:contacts]
    expect(auth.uid).to start_with('ks_')
    expect(auth.extra.claims).to eq('email' => PartnerStub::EMAILS)
    expect(auth.credentials.refresh_token).to eq('r1')
  end
end
