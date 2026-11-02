# frozen_string_literal: true

require_relative 'lib/omniauth/vitsme/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-vitsme'
  spec.version = OmniAuth::Vitsme::VERSION
  spec.authors = ['Yuval Tobias']
  spec.email = ['yuval@mattyr.com']

  spec.summary = 'OmniAuth strategy for vits.me identity verification'
  spec.description = 'Sign people in with vits.me, verify details about them, and gate sign-up by ' \
                     'nationality — an OpenID Connect strategy with identity matching, typed claims and ' \
                     'a machine-readable claim catalog.'
  spec.homepage = 'https://github.com/yuvaltobias/omniauth-vitsme'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.3'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri'] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['documentation_uri'] = "#{spec.homepage}#readme"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").select do |f|
      f.start_with?('lib/', 'data/') || %w[README.md CHANGELOG.md LICENSE.txt AGENTS.md llms.txt].include?(f)
    end
  end
  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth_openid_connect', '~> 0.8'
end
