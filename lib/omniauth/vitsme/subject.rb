# frozen_string_literal: true

require 'base64'
require 'json'

module OmniAuth
  module Vitsme
    # The person an ask is about: what your `ask_about:` lambda returns, as vits.me is told it.
    #
    # vits.me tells a sign-in from an ask by whether the request names its subject. A sign-in names nobody and
    # asks only who the person is (`openid` and gates). An ask names the person already signed in to your app,
    # and only an ask may carry a detail scope, go to a partner or start a trip. `ask_about:` returns the
    # vits.me ID token you kept for the signed-in person (`auth.credentials.id_token`), or the uid you store
    # for them. For a request to vits.me itself the gem sends its `sub` (OpenID Connect Core §5.5.1, the
    # "plain subject"); for a partner or a trip it sends the ID token, encrypted to vits.me (§3.1.2.1,
    # `id_token_hint`, the "sealed subject").
    module Subject
      module_function

      # The uid an `ask_about:` value names: the `sub` of an ID token, or the value itself. Empty for nobody.
      # The token is not verified here: it names whom you mean, and vits.me and the callback check the
      # answer is about that person.
      def uid(value)
        value = value.to_s
        return value unless id_token?(value)

        payload(value).fetch('sub', '').to_s
      end

      def id_token?(value) = value.to_s.match?(/\A[\w-]+\.[\w-]+\.[\w-]*\z/)

      def payload(id_token)
        part = id_token.to_s.split('.')[1].to_s
        JSON.parse(Base64.urlsafe_decode64(part + ('=' * (-part.length % 4))))
      rescue ArgumentError, JSON::ParserError
        {}
      end
    end
  end
end
