# frozen_string_literal: true

RSpec.describe OmniAuth::Vitsme::Image do
  let(:jpeg) { "\xFF\xD8\xFF\xE0\x00\x10JFIF".b + ('x' * 64) + "\xFF\xD9".b }
  let(:claim) do
    { 'content_type' => 'image/jpeg', 'width' => 480, 'height' => 640, 'content' => Base64.strict_encode64(jpeg) }
  end

  def decoded(**changes) = described_class.from_claim(claim.merge(changes.transform_keys(&:to_s)))

  it 'decodes the claim vits.me sends' do
    image = described_class.from_claim(claim)
    expect(image.data).to eq(jpeg)
    expect([image.content_type, image.width, image.height]).to eq(['image/jpeg', 480, 640])
    expect(image.io.read).to eq(jpeg)
  end

  it 'drops another type, and bytes that are not a JPEG' do
    expect(decoded(content_type: 'image/png')).to be_nil
    expect(decoded(content: Base64.strict_encode64("\x89PNG\r\n".b))).to be_nil
  end

  it 'drops loose base64 and a picture over the size vits.me promises' do
    expect(decoded(content: Base64.encode64(jpeg * 4))).to be_nil # line breaks
    big = "\xFF\xD8\xFF".b + ('x' * described_class.max_bytes)
    expect(decoded(content: Base64.strict_encode64(big))).to be_nil
  end

  it 'drops what is not an object' do
    expect(described_class.from_claim('not an object')).to be_nil
    expect(described_class.from_claim(nil)).to be_nil
  end

  it 'never shows the picture in an inspect' do
    expect(described_class.from_claim(claim).inspect).to eq('#<OmniAuth::Vitsme::Image image/jpeg 480x640 76 bytes>')
  end

  it 'is the typed portrait in the auth hash, and kept out of raw_info and info' do
    auth = OmniAuth::Vitsme::Test.auth_hash(claims: { portrait: described_class.from_claim(claim) })
    expect(auth.extra.claims['portrait'].data).to eq(jpeg)
    expect(auth.extra.raw_info).not_to have_key('portrait')
    expect(auth.info.to_h.keys).not_to include('portrait', 'image')
  end

  it 'types it from a raw UserInfo response the way the strategy does' do
    shape = OmniAuth::Vitsme::AuthShape
    expect(shape.claims('sub' => 'solid_x', 'portrait' => claim)['portrait'].data).to eq(jpeg)
    expect(shape.claims('portrait' => claim.merge('content' => '!!!'))).not_to have_key('portrait')
  end
end
