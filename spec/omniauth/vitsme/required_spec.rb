# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Required do
  it 'tells the starred scopes from the rest, by their plain names' do
    scopes = %i[openid full_name__intl* nationality age__over_18* full_name__intl*]
    expect(described_class.names(scopes)).to eq(%w[full_name__intl age__over_18])
    expect(described_class.plain_all(scopes)).to eq(%w[openid full_name__intl nationality age__over_18 full_name__intl])
  end

  it 'refuses a star on nothing, and, for vits.me, on what is not a detail' do
    expect { described_class.check!(%w[*], 'here') }.to raise_error(ArgumentError, /here requires \*;/)
    expect do
      described_class.check!(%w[openid*], 'here', identity: true)
    end.to raise_error(ArgumentError, /only a detail/)
    expect { described_class.check!(%w[openid_nationality__il*], 'here', identity: true) }.to raise_error(ArgumentError)
    expect { described_class.check!(%w[email*], 'a partner') }.not_to raise_error
  end

  it "finds a required scope missing from vits.me's answer, where false is an answer and absent is not" do
    scopes = %w[openid age__over_18* full_name__intl*]
    expect(described_class.missing_at_vitsme(scopes,
                                             { age__over_18: false, full_name__intl: 'Dana Cohen' })).to be_empty
    expect(described_class.missing_at_vitsme(scopes, { 'age__over_18' => true })).to eq(%w[full_name__intl])
  end

  it "finds a required scope missing from a partner's answer, which is an empty list for one not given" do
    expect(described_class.missing_at_partner(%w[email* phone], { 'email' => [{}], 'phone' => [] })).to be_empty
    expect(described_class.missing_at_partner(%w[email*], { 'email' => [] })).to eq(%w[email])
    expect(described_class.missing_at_partner(%w[email*], {})).to eq(%w[email])
  end
end
