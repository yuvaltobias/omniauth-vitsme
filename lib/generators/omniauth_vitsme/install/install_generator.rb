# frozen_string_literal: true

require 'rails/version'
require 'rails/generators'
require 'rails/generators/migration'
require 'omniauth/vitsme'

module OmniAuth
  module Vitsme
    module Generators
      # bin/rails g omniauth_vitsme:install [--model=User] [--verify=age__over_18 name] [--gate=IL] [--fluid]
      #
      # Sign-in with vits.me wired the way the README describes: an initializer, a callbacks controller
      # that finds a returning person by every uid vits.me lists for them, failure messages (en/he), a
      # sign-in button partial, routes, and a migration adding a private, unique `vitsme_uid` column.
      # --verify adds a second provider that asks about the person already signed in, with expected_uid.
      class InstallGenerator < Rails::Generators::Base
        include Rails::Generators::Migration

        namespace 'omniauth_vitsme:install'
        source_root File.expand_path('templates', __dir__)

        class_option :model, type: :string, default: 'User', desc: 'The model a vits.me uid signs in as'
        class_option :scope, type: :array, default: [], desc: 'Disclosure scopes to ask for at sign-in'
        class_option :verify, type: :array, default: [],
                              desc: 'Scopes for a :vitsme_verify provider about the signed-in person'
        class_option :gate, type: :array, default: [], desc: 'Nationalities (ISO alpha-2) required to sign in'
        class_option :fluid, type: :boolean, default: false, desc: 'Also sign in people pending verification'

        def self.next_migration_number(_dirname)
          Time.now.utc.strftime('%Y%m%d%H%M%S')
        end

        def check_options
          scopes = sign_in_scopes + verify_scopes
          unknown = scopes.reject { |s| Catalog.known_scope?(s) }
          raise Thor::Error, "Unknown vits.me scope(s): #{unknown.join(', ')}" unless unknown.empty?
          return unless options[:fluid] && !options[:gate].empty?

          raise Thor::Error, '--fluid and --gate cannot be combined: a gate admits verified people only.'
        end

        def create_initializer
          template 'omniauth_vitsme.rb.tt', 'config/initializers/omniauth_vitsme.rb'
        end

        def create_controller
          template 'vitsme_callbacks_controller.rb.tt', 'app/controllers/vitsme_callbacks_controller.rb'
        end

        def create_views_and_locales
          template '_sign_in.html.erb.tt', 'app/views/vitsme/_sign_in.html.erb'
          copy_file 'vitsme.en.yml', 'config/locales/vitsme.en.yml'
          copy_file 'vitsme.he.yml', 'config/locales/vitsme.he.yml'
        end

        def add_uid_migration
          migration_template 'add_vitsme_uid.rb.tt', "db/migrate/add_vitsme_uid_to_#{table_name}.rb"
        end

        def add_routes
          route "get '/auth/vitsme_verify/callback', to: 'vitsme_callbacks#verify'" if verify?
          route "get '/auth/failure', to: 'vitsme_callbacks#failure'"
          route "get '/auth/vitsme/callback', to: 'vitsme_callbacks#sign_in'"
        end

        def next_steps
          say <<~TEXT

            vits.me sign-in is wired. Next:
              1. Ask the vits.me team for client credentials; set VITSME_CLIENT_ID / VITSME_CLIENT_SECRET.
                 Register #{callback_urls.join(' and ')} as redirect URIs.
              2. Add gem "omniauth-rails_csrf_protection" (OmniAuth 2 signs in by POST only).
              3. bin/rails db:migrate, then render "vitsme/sign_in" where people sign in.
              4. Read the uid rules in the omniauth-vitsme README: store it, never show or log it.
          TEXT
        end

        private

        def model
          options[:model].camelize
        end

        def session_key
          "#{options[:model].underscore.tr('/', '_')}_id"
        end

        def table_name
          options[:model].underscore.tr('/', '_').pluralize
        end

        def sign_in_scopes
          (['openid'] + options[:scope] + (options[:fluid] ? ['fluid'] : [])).uniq
        end

        def verify_scopes
          options[:verify].empty? ? [] : (['openid'] + options[:verify]).uniq
        end

        def verify?
          !options[:verify].empty?
        end

        def gate
          options[:gate].map(&:upcase)
        end

        def symbols(list)
          "%i[#{list.join(' ')}]"
        end

        def callback_urls
          paths = ['/auth/vitsme/callback']
          paths << '/auth/vitsme_verify/callback' if verify?
          paths.map { |p| "https://<your host>#{p}" }
        end

        def migration_version
          "[#{Rails::VERSION::MAJOR}.#{Rails::VERSION::MINOR}]"
        end
      end
    end
  end
end
