# frozen_string_literal: true

require 'base64'
require 'stringio'

module OmniAuth
  module Vitsme
    # A picture claim (`portrait`), decoded: the JPEG vits.me sent, with its size. vits.me sends it whole, in
    # UserInfo, so your app keeps its own copy:
    #
    #   if (photo = auth.extra.claims['portrait'])
    #     user.photo.attach(io: photo.io, filename: 'portrait.jpg', content_type: photo.content_type)
    #   end
    #
    # Read only from what vits.me promises: a JPEG (by its bytes, not only its label) in strict base64, no
    # larger than MAX_BYTES. Anything else is dropped (nil), never guessed at.
    Image = Struct.new(:content_type, :width, :height, :data, keyword_init: true) do
      def io = StringIO.new(data)
      def bytesize = data.bytesize

      # The claim as vits.me sends it, for OmniAuth::Vitsme::Test.
      def to_claim
        { 'content_type' => content_type, 'width' => width, 'height' => height,
          'content' => Base64.strict_encode64(data) }
      end

      # The bytes are a person's face: never in an inspect, a log line or an exception message.
      def inspect = "#<OmniAuth::Vitsme::Image #{content_type} #{width}x#{height} #{bytesize} bytes>"
      alias_method :to_s, :inspect
    end

    class << Image
      MAX_BYTES = 200 * 1024
      JPEG_MAGIC = "\xFF\xD8\xFF".b

      def max_bytes = MAX_BYTES

      # An Image from the claim's JSON value, or nil.
      def from_claim(value)
        return value if value.is_a?(Image)
        return nil unless value.is_a?(Hash)

        value = value.transform_keys(&:to_s)
        data = jpeg_bytes(value)
        return nil unless data

        new(content_type: 'image/jpeg', width: dimension(value['width']), height: dimension(value['height']),
            data: data)
      end

      private

      # The decoded content, if it is what vits.me promises: a JPEG label, strict base64, JPEG bytes, in size.
      def jpeg_bytes(value)
        content = value['content']
        return nil unless value['content_type'] == 'image/jpeg' && content.is_a?(String)
        return nil if content.bytesize > (MAX_BYTES * 4 / 3) + 4 # refused before it is decoded

        data = Base64.strict_decode64(content)
        data if data.bytesize <= MAX_BYTES && data.start_with?(JPEG_MAGIC)
      rescue ArgumentError
        nil
      end

      def dimension(value) = value.is_a?(Integer) && value.positive? ? value : nil
    end
  end
end
