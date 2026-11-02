# frozen_string_literal: true

require 'tmpdir'
require 'generators/omniauth_vitsme/install/install_generator'

RSpec.describe OmniAuth::Vitsme::Generators::InstallGenerator do
  let(:root) { Dir.mktmpdir }

  before do
    FileUtils.mkdir_p(File.join(root, 'config'))
    File.write(File.join(root, 'config/routes.rb'), "Rails.application.routes.draw do\nend\n")
  end

  after { FileUtils.remove_entry(root) }

  def generate(*args)
    $stdout = StringIO.new
    described_class.start(args, destination_root: root)
  ensure
    $stdout = STDOUT
  end

  def read(path)
    File.read(File.join(root, path))
  end

  it 'answers to omniauth_vitsme:install' do
    expect(described_class.namespace).to eq('omniauth_vitsme:install')
  end

  context 'with defaults' do
    before { generate }

    it 'writes a sign-in provider with no verify provider' do
      initializer = read('config/initializers/omniauth_vitsme.rb')
      expect(initializer).to include('provider :vitsme, vitsme.merge(', 'scope: %i[openid]')
      expect(initializer).not_to include('vitsme_verify', 'nationality_gate')
    end

    it 'finds returning people by every uid vits.me lists, and never logs the auth hash' do
      controller = read('app/controllers/vitsme_callbacks_controller.rb')
      expect(controller).to include('auth.extra.lookup_uids + auth.extra.fluid_uids',
                                    'User.create!(vitsme_uid: auth.uid)')
      expect(controller).not_to match(/logger|Rails\.logger|puts/)
    end

    it 'adds a unique vitsme_uid to users' do
      migration = Dir[File.join(root, 'db/migrate/*_add_vitsme_uid_to_users.rb')].first
      expect(File.read(migration)).to include('add_index :users, :vitsme_uid, unique: true',
                                              "ActiveRecord::Migration[#{Rails::VERSION::MAJOR}.")
    end

    it 'routes the callback and the failure page' do
      expect(read('config/routes.rb')).to include("'/auth/vitsme/callback'", "'/auth/failure'")
    end

    it 'writes failure messages for every failure type, in English and Hebrew' do
      types = OmniAuth::Strategies::Vitsme::FAILURES + [:access_denied]
      %w[en he].each do |locale|
        messages = YAML.safe_load(read("config/locales/vitsme.#{locale}.yml")).dig(locale, 'vitsme', 'failures')
        expect(messages.keys).to include(*types.map(&:to_s))
      end
    end

    # People on a site are "verified", not "vits.me-verified".
    it 'never names vits.me in copy people read' do
      %w[en he].each do |locale|
        leaves = ->(node) { node.is_a?(Hash) ? node.values.flat_map(&leaves) : [node] }
        strings = leaves.call(YAML.safe_load(read("config/locales/vitsme.#{locale}.yml")))
        expect(strings).to all(satisfy { |s| !s.match?(/vits\.?me|it.s\.me/i) })
      end
    end
  end

  context 'with a model, verify scopes and a gate' do
    before { generate('--model=Account', '--scope=name', '--verify=age__over_18', '--gate=il') }

    it 'gates sign-in and adds a verify provider bound to the signed-in account' do
      initializer = read('config/initializers/omniauth_vitsme.rb')
      expect(initializer).to include('scope: %i[openid name]', 'nationality_gate: %w[IL]', 'name: :vitsme_verify',
                                     'scope: %i[openid age__over_18]',
                                     "Account.find_by(id: env['rack.session']['account_id'])&.vitsme_uid")
    end

    it 'routes and handles the verify callback' do
      expect(read('config/routes.rb')).to include("'/auth/vitsme_verify/callback', to: 'vitsme_callbacks#verify'")
      expect(read('app/controllers/vitsme_callbacks_controller.rb')).to include('def verify')
    end

    it 'loads as Ruby' do
      expect { RubyVM::InstructionSequence.compile(read('config/initializers/omniauth_vitsme.rb')) }.not_to raise_error
      expect { RubyVM::InstructionSequence.compile(read('app/controllers/vitsme_callbacks_controller.rb')) }
        .not_to raise_error
    end
  end

  it 'refuses an unknown scope' do
    expect { generate('--verify=id_number') }.to raise_error(SystemExit).or output.to_stderr
  end
end
