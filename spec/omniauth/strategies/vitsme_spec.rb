# frozen_string_literal: true

require "spec_helper"

class DummyApp
  def call(_env); end
end

module OmniAuth
  module Strategies
    RSpec.describe Vitsme do
      let(:app) { DummyApp.new }

      let(:strategy) do
        described_class.new(app).tap do |s|
          s.options.client_options.identifier = "test_client_id"
          s.options.client_options.secret = "test_client_secret"
        end
      end

      describe "default options" do
        it "has the correct provider name" do
          expect(strategy.options.name).to eq("vitsme")
        end

        it "enables OIDC discovery" do
          expect(strategy.options.discovery).to be true
        end

        it "sets the issuer to vits.me" do
          expect(strategy.options.issuer).to eq("https://vits.me")
        end

        it "uses RS256 signing algorithm" do
          expect(strategy.options.client_signing_alg).to eq(:RS256)
        end

        it "requests only openid scope by default" do
          expect(strategy.options.scope).to eq([:openid])
        end

        it "uses authorization code flow" do
          expect(strategy.options.response_type).to eq("code")
        end

        it "uses query response mode" do
          expect(strategy.options.response_mode).to eq("query")
        end
      end

      describe "client_options defaults" do
        let(:client_opts) { strategy.options.client_options }

        it "sets scheme to https" do
          expect(client_opts.scheme).to eq("https")
        end

        it "sets host to vits.me" do
          expect(client_opts.host).to eq("vits.me")
        end

        it "sets port to 443" do
          expect(client_opts.port).to eq(443)
        end

        it "sets authorization_endpoint" do
          expect(client_opts.authorization_endpoint).to eq("/oauth/authorize")
        end

        it "sets token_endpoint" do
          expect(client_opts.token_endpoint).to eq("/oauth/token")
        end

        it "sets userinfo_endpoint" do
          expect(client_opts.userinfo_endpoint).to eq("/oauth/userinfo")
        end

        it "sets jwks_uri" do
          expect(client_opts.jwks_uri).to eq("/oauth/discovery/keys")
        end
      end

      describe "client_id / client_secret convenience options" do
        let(:strategy) do
          described_class.new(app).tap do |s|
            s.options.client_id = "flat_client_id"
            s.options.client_secret = "flat_client_secret"
          end
        end

        it "bridges client_id to client_options.identifier" do
          opts = strategy.send(:client_options)
          expect(opts.identifier).to eq("flat_client_id")
        end

        it "bridges client_secret to client_options.secret" do
          opts = strategy.send(:client_options)
          expect(opts.secret).to eq("flat_client_secret")
        end
      end

      describe "info hash" do
        let(:user_info_response) do
          OpenStruct.new(
            raw_attributes: {
              "sub" => "pairwise-subject-id-123",
              "name" => "Jane Doe",
              "given_name" => "Jane",
              "family_name" => "Doe",
              "email" => "jane@example.com",
              "birthdate" => "1990-01-15",
              "nationality" => "IL",
              "age__over_18" => true,
              "age__over_21" => true
            }
          )
        end

        before do
          allow(strategy).to receive(:user_info).and_return(user_info_response)
        end

        it "returns the correct uid" do
          expect(strategy.uid).to eq("pairwise-subject-id-123")
        end

        it "returns name in info" do
          expect(strategy.info[:name]).to eq("Jane Doe")
        end

        it "returns first_name in info" do
          expect(strategy.info[:first_name]).to eq("Jane")
        end

        it "returns last_name in info" do
          expect(strategy.info[:last_name]).to eq("Doe")
        end

        it "returns email in info" do
          expect(strategy.info[:email]).to eq("jane@example.com")
        end

        it "returns birthday in info" do
          expect(strategy.info[:birthday]).to eq("1990-01-15")
        end

        it "returns nationality in info" do
          expect(strategy.info[:nationality]).to eq("IL")
        end

        it "returns age verification flags" do
          expect(strategy.info[:age_over_18]).to be true
          expect(strategy.info[:age_over_21]).to be true
        end

        it "omits nil values from info" do
          expect(strategy.info).not_to have_key(:age_over_13)
        end

        it "provides raw_info in extra" do
          expect(strategy.extra[:raw_info]["sub"]).to eq("pairwise-subject-id-123")
        end
      end

      describe "info hash with name__full fallback" do
        let(:user_info_response) do
          OpenStruct.new(
            raw_attributes: {
              "sub" => "abc",
              "name__full" => "Full Name Here"
            }
          )
        end

        before do
          allow(strategy).to receive(:user_info).and_return(user_info_response)
        end

        it "falls back to name__full when name is absent" do
          expect(strategy.info[:name]).to eq("Full Name Here")
        end
      end
    end
  end
end
