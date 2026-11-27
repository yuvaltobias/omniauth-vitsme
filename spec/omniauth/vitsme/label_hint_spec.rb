# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::LabelHint do
  it 'makes space-separated scope:label pairs, symbols or strings, in the order given' do
    expect(described_class.param({ email: :work, 'phone' => 'mobile', 'address.declared' => :home },
                                 %w[email phone address.declared]))
      .to eq('email:work phone:mobile address.declared:home')
  end

  it 'keeps only well-formed pairs under a scope asked, and gives nil when none is left' do
    hint = { email: 'work', phone: 'mobile', 'web site' => 'blog', link: 'home page', website: 'a:b', school: '' }
    expect(described_class.pairs(hint, ['email', 'web site', 'link', 'website', 'school'])).to eq('email' => 'work')
    expect(described_class.param({ phone: :mobile }, %w[email])).to be_nil
    expect(described_class.param(nil, %w[email])).to be_nil
    expect(described_class.param('email:work', %w[email])).to be_nil
  end

  describe '.check!' do
    def check(hint, scope = %w[email phone]) = described_class.check!(hint, scope, 'stop https://acme.test')

    it 'passes a well-formed hint, or none' do
      expect { check({ email: :work, phone: 'mobile' }) }.not_to raise_error
      expect { check(nil) }.not_to raise_error
    end

    it 'raises for a hint that is not a Hash, a malformed pair, or a scope not asked' do
      expect { check('email:work') }.to raise_error(ArgumentError, %r{stop https://acme.test label_hint: is a Hash})
      expect { check({ email: 'home page' }) }.to raise_error(ArgumentError, /"email:home page" is not a scope/)
      expect { check({ email: 'a:b' }) }.to raise_error(ArgumentError, /without spaces or colons/)
      expect { check({ email: nil }) }.to raise_error(ArgumentError, /"email:"/)
      expect { check({ link: :blog }) }.to raise_error(ArgumentError, /names link, a scope it does not ask/)
    end
  end
end
