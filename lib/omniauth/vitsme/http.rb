# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module OmniAuth
  module Vitsme
    # The few HTTPS calls the gem makes outside the OpenID Connect flow: KNOT claims, fresh introductions
    # and published keys. Short timeouts; any transport failure is HTTP::Unavailable.
    module HTTP
      TIMEOUT = 5

      class Unavailable < StandardError; end

      Response = Struct.new(:status, :body) do
        def ok? = status.between?(200, 299)
        def json = JSON.parse(body)
      end

      module_function

      def get(url, headers = {})
        request(Net::HTTP::Get.new(URI(url), headers))
      end

      def post_form(url, form, basic: nil, headers: {})
        req = Net::HTTP::Post.new(URI(url), headers)
        req.set_form_data(form)
        req.basic_auth(*basic) if basic
        request(req)
      end

      def post_json(url, body, headers: {})
        req = Net::HTTP::Post.new(URI(url),
                                  headers.merge('Content-Type' => 'application/json', 'Accept' => 'application/json'))
        req.body = JSON.generate(body)
        request(req)
      end

      def request(req)
        uri = req.uri
        response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                                       open_timeout: TIMEOUT, read_timeout: TIMEOUT) do |http|
          http.request(req)
        end
        Response.new(response.code.to_i, response.body.to_s)
      rescue SocketError, SystemCallError, IOError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError => e
        raise Unavailable, e.class.name
      end
    end
  end
end
