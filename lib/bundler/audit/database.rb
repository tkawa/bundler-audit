#
# Copyright (c) 2013 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <http://www.gnu.org/licenses/>.
#

require 'bundler/audit/advisory'

require 'time'
require 'yaml'

module Bundler
  module Audit
    #
    # Represents the directory of advisories, grouped by gem name
    # and CVE number.
    #
    class Database

      # Git URL of the ruby-advisory-db
      URL = 'https://github.com/rubysec/ruby-advisory-db.git'

      # Path to the user's copy of the ruby-advisory-db
      PATH = File.expand_path(File.join(ENV['HOME'],'.local','share','ruby-advisory-db'))

      # The path to the advisory database
      attr_reader :path

      #
      # Initializes the Advisory Database.
      #
      # @param [String] path
      #   The path to the advisory database.
      #
      # @raise [ArgumentError]
      #   The path was not a directory.
      #
      def initialize(path=self.class.path)
        unless File.directory?(path)
          raise(ArgumentError,"#{path.dump} is not a directory")
        end

        @path = path
      end

      #
      # The default path for the database.
      #
      # @return [String]
      #   The path to the database directory. Defaults to {PATH}.
      #
      def self.path
        @@path ||= PATH
      end

      #
      # Sets the default path for the database.
      #
      # @return [String]
      #   The new default path for the database.
      #
      def self.path=(new_path)
        @@path = new_path
      end

      #
      # Downloads the database.
      #
      # @return [Boolean]
      #   Specifies whether the download was successful.
      #
      # @since 0.4.0
      #
      def self.install!
        system 'git', 'clone', URL, path
      end

      #
      # Updates the user's ruby-advisory-db.
      #
      # @return [Boolean]
      #   Specifies whether the update was successful.
      #
      # @see #update!
      #
      # @since 0.3.0
      #
      def self.update!
        if File.directory?(path)
          new(path).update!
        else
          download!
        end
      end

      #
      # Updates the database.
      #
      # @return [Boolean]
      #   Specifies whether the update was successful.
      #
      # @note
      #   Requires network access.
      #
      # @see 0.4.0
      #
      def update!
        Dir.chdir(@path) do
          system 'git', 'pull', 'origin', 'master'
        end
      end

      #
      # Determines when the database was last updated.
      #
      # @return [Time]
      #   The time of the last update.
      #
      # @since 0.4.0
      #
      def last_updated
        Dir.chdir(@path) { Time.parse(`git log -1 --format=%ad`) }
      end

      #
      # Enumerates over every advisory in the database.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed each advisory.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory from the database.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories(&block)
        return enum_for(__method__) unless block_given?

        each_advisory_path do |path|
          yield Advisory.load(path)
        end
      end

      #
      # Enumerates over advisories for the given gem.
      #
      # @param [String] name
      #   The gem name to lookup.
      #
      # @yield [advisory]
      #   If a block is given, each advisory for the given gem will be yielded.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory for the given gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories_for(name)
        return enum_for(__method__,name) unless block_given?

        each_advisory_path_for(name) do |path|
          yield Advisory.load(path)
        end
      end

      #
      # Verifies whether the gem is effected by any advisories.
      #
      # @param [Gem::Specification] gem
      #   The gem to verify.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed advisories that effect
      #   the gem.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory that effects the specific version of the gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def check_gem(gem)
        return enum_for(__method__,gem) unless block_given?

        advisories_for(gem.name) do |advisory|
          if advisory.vulnerable?(gem.version)
            yield advisory
          end
        end
      end

      #
      # The number of advisories within the database.
      #
      # @return [Integer]
      #   The number of advisories.
      #
      def size
        each_advisory_path.count
      end

      #
      # Converts the database to a String.
      #
      # @return [String]
      #   The path to the database.
      #
      def to_s
        @path
      end

      #
      # Inspects the database.
      #
      # @return [String]
      #   The inspected database.
      #
      def inspect
        "#<#{self.class}:#{self}>"
      end

      protected

      #
      # Enumerates over every advisory path in the database.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      def each_advisory_path(&block)
        Dir.glob(File.join(@path,'gems','*','*.yml'),&block)
      end

      #
      # Enumerates over the advisories for the given gem.
      #
      # @param [String] name
      #   The gem of the gem.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      def each_advisory_path_for(name,&block)
        Dir.glob(File.join(@path,'gems',name,'*.yml'),&block)
      end

    end
  end
end
