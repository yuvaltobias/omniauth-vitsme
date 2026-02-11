# frozen_string_literal: true

require_relative "lib/omniauth/vitsme/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-vitsme"
  spec.version = OmniAuth::Vitsme::VERSION
  spec.authors = ["Your Name"]
  spec.email = ["your.email@example.com"]

  spec.summary = "OmniAuth strategy for vits.me (itsme) identity verification"
  spec.description = "OmniAuth OpenID Connect strategy for vits.me (itsme), " \
                     "the Belgian digital identity platform."
  spec.homepage = "https://github.com/example/omniauth-vitsme"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?("spec/", "test/", ".git", ".github", "Gemfile")
    end
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "omniauth_openid_connect", "~> 0.8"
end
