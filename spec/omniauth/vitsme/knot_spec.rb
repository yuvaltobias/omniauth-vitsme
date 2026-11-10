# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Knot do
  let(:client_id) { VitsMeStub::CLIENT_ID }

  describe '.resolve' do
    it 'fetches each source and keeps the claims it names, verified' do
      KnotStub.stub
      result = described_class.resolve(KnotStub.distributed, client_id: client_id)
      expect(result.claims).to eq('widgets' => KnotStub::WIDGETS)
      expect(result.errors).to be_empty
    end

    it 'leaves the claim out, and says why, when the answer is for another transaction, site or signer' do
      KnotStub.stub(answer_for: 'someone-else')
      expect(described_class.resolve(KnotStub.distributed,
                                     client_id: client_id).errors).to eq('acme' => 'answer for another transaction')

      KnotStub.stub(aud: 'another-site')
      expect(described_class.resolve(KnotStub.distributed,
                                     client_id: client_id).errors).to eq('acme' => 'not addressed to you')

      KnotStub.stub(key: OpenSSL::PKey::RSA.new(2048))
      result = described_class.resolve(KnotStub.distributed, client_id: client_id)
      expect(result.claims).to be_empty
      expect(result.errors.keys).to eq(['acme'])
    end

    it 'refuses an unsigned answer' do
      KnotStub.stub
      unsigned = JSON::JWT.new(iss: KnotStub::ISSUER, aud: client_id, sub: 'txn-1', exp: Time.now.to_i + 60,
                               'widgets' => KnotStub::WIDGETS).to_s
      WebMock.stub_request(:get, KnotStub::ENDPOINT).to_return(body: unsigned)
      expect(described_class.resolve(KnotStub.distributed, client_id: client_id).claims).to be_empty
    end

    it 'records a KNOT that cannot be reached, without raising' do
      KnotStub.stub(status: 503)
      expect(described_class.resolve(KnotStub.distributed, client_id: client_id).errors).to eq('acme' => 'HTTP 503')
    end
  end

  describe '.fresh_claims' do
    let(:uid) { OmniAuth::Vitsme::Test.uid }

    def ask
      described_class.fresh_claims(uid: uid, scopes: %w[knot:acme:widgets], client_id: client_id,
                                   client_secret: 'secret')
    end

    def stub_introductions(status:, body: KnotStub.distributed)
      WebMock.stub_request(:post, 'https://vits.me/knot/introductions')
             .with(basic_auth: [client_id, 'secret'], body: { sub: uid, scope: 'knot:acme:widgets' })
             .to_return(status: status, headers: { 'Content-Type' => 'application/json' }, body: body.to_json)
    end

    it 'asks vits.me for a new introduction, then the KNOT' do
      stub_introductions(status: 200)
      KnotStub.stub
      expect(ask.claims).to eq('widgets' => KnotStub::WIDGETS)
    end

    it 'says when the person no longer lets the site be told, or the credentials are wrong' do
      stub_introductions(status: 403, body: { error: 'consent_required' })
      expect { ask }.to raise_error(described_class::ConsentRequired)
      stub_introductions(status: 401, body: { error: 'invalid_client' })
      expect { ask }.to raise_error(described_class::InvalidClient)
    end
  end

  it 'accepts any KNOT scope, knowing no partner' do
    expect(described_class.scope?('knot:acme:widgets')).to be(true)
    expect(described_class.scope?('knot:someone-new:Anything.At.All')).to be(true)
    expect(described_class.scope?('knot:acme')).to be(false)
    expect(OmniAuth::Vitsme::Catalog.known_scope?('knot:someone-new:thing')).to be(true)
  end

  describe '.scopes' do
    it 'reads the active KNOT scopes as vits.me describes them now' do
      listed = [{ 'scope' => 'knot:acme:widgets', 'knot' => 'Acme', 'claim' => 'widgets',
                  'documentation_url' => 'https://acme.test/docs' }]
      WebMock.stub_request(:get, 'https://vits.me/knot/scopes')
             .to_return(headers: { 'Content-Type' => 'application/json' }, body: { knot_scopes: listed }.to_json)
      expect(described_class.scopes).to eq(listed)
    end

    it 'says when vits.me cannot be asked' do
      WebMock.stub_request(:get, 'https://vits.me/knot/scopes').to_return(status: 503)
      expect { described_class.scopes }.to raise_error(described_class::Unavailable)
    end
  end
end
