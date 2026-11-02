# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Catalog do
  # The scopes vits.me offers (config/initializers/doorkeeper.rb `optional_scopes`, gates aside).
  # A new vits.me scope must land here too — see vitsme/docs/adding-vitsme-scope.md in the mono-repo.
  let(:vits_me_scopes) do
    %w[openid fluid name name__full nationality nationality__in_eu nationality__in_eea nationality__in_esm
       nationality__gdpr_compliant il_government_id_number age age__years age__range age__over_13
       age__over_18 age__over_21 birthday birthdate birthyear]
  end

  it 'knows exactly the scopes vits.me offers' do
    expect(described_class.scopes).to match_array(vits_me_scopes)
  end

  it 'describes and types every claim' do
    described_class.claims.each do |name, spec|
      expect(spec).to include('scope', 'type', 'description'), "#{name} is incomplete"
      expect(%w[string boolean integer string_array]).to include(spec['type']), "#{name} has an unknown type"
    end
  end

  it 'recognises gate scopes by country code' do
    expect(described_class.gate_scope?('openid_nationality__il')).to be(true)
    expect(described_class.gate_scope?('openid_nationality__isr')).to be(false)
    expect(described_class.known_scope?(:openid_nationality__us)).to be(true)
  end

  it 'maps every refusal reason to an OmniAuth failure type the strategy documents' do
    reasons = described_class::DATA['refusals'].keys
    expect(reasons.map { |r| described_class.failure_for(r) })
      .to all(satisfy { |t| (OmniAuth::Strategies::Vitsme::FAILURES + [:access_denied]).include?(t) })
    expect(described_class.failure_for('something_new')).to be_nil
  end

  describe '.coerce' do
    it 'reads booleans from JSON booleans and from the strings older servers sent' do
      expect(described_class.coerce(:age__over_18, true)).to be(true)
      expect(described_class.coerce(:age__over_18, 'false')).to be(false)
      expect(described_class.coerce(:age__over_18, 'maybe')).to be_nil
    end

    it 'reads integers and drops what is not one' do
      expect(described_class.coerce(:age__years, '37')).to eq(37)
      expect(described_class.coerce(:age__years, 37)).to eq(37)
      expect(described_class.coerce(:age__years, 'gen_x')).to be_nil
    end

    it 'keeps absent values absent' do
      expect(described_class.coerce(:name, nil)).to be_nil
      expect(described_class.coerce(:name, '')).to be_nil
    end
  end
end
