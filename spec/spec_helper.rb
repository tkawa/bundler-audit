require 'rspec'
require 'tmpdir'

require 'bundler/audit/version'

module Helpers
  def sh(command, options={})
    Bundler.with_clean_env do
      result = `#{command} 2>&1`
      raise "FAILED #{command}\n#{result}" if $?.success? == !!options[:fail]
      result
    end
  end

  def decolorize(string)
    string.gsub(/\e\[\d+m/, "")
  end
end

include Bundler::Audit

RSpec.configure do |config|
  config.include Helpers

  config.before(:suite) do
    Database.path = Dir.mktmpdir('ruby-advisory-db')
  end
end
