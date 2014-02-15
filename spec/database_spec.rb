require 'spec_helper'
require 'bundler/audit/database'
require 'tmpdir'
require 'rake/file_list'

describe Bundler::Audit::Database do
  describe "update!" do
    context "when PATH does not exist yet" do
      before do
        FileUtils.rm_rf(described_class.path)
      end

      it "should create the path as needed" do
        described_class.update!

        expect(File.directory?(described_class.path)).to be_true
      end
    end

    context "when PATH does exist" do
      before(:all) do
        @t1 = Dir.chdir(described_class.path) do
          system 'git', 'reset', '--hard', 'HEAD^1'
          
          Time.parse(`git log -1 --format=%ad`)
        end

        described_class.update!

        @t2 = Dir.chdir(described_class.path) do
          Time.parse(`git log -1 --format=%ad`)
        end
      end

      it "should update the git repository" do
        expect(@t2).to be > @t1
      end
    end
  end

  describe "#initialize" do
    context "when given no arguments" do
      subject { described_class.new }

      it "should set path to the default path" do
        expect(subject.path).to be == described_class.path
      end
    end

    context "when given a directory" do
      let(:path ) { Dir.tmpdir }

      subject { described_class.new(path) }

      it "should set #path" do
        subject.path.should == path
      end
    end

    context "when given an invalid directory" do
      it "should raise an ArgumentError" do
        lambda {
          described_class.new('/foo/bar/baz')
        }.should raise_error(ArgumentError)
      end
    end
  end

  describe "#update!" do
    before do
      @t1 = Dir.chdir(subject.path) do
        system 'git', 'reset', '--hard', 'HEAD^1'

        Time.parse(`git log -1 --format=%ad`)
      end

      described_class.update!

      @t2 = Dir.chdir(subject.path) do
        Time.parse(`git log -1 --format=%ad`)
      end
    end

    it "should update the git repository" do
      expect(@t2).to be > @t1
    end
  end

  describe "#last_updated" do
    let(:timestamp) do
      Dir.chdir(subject.path) { Time.parse(`git log -1 --format=%ad`) }
    end

    it "should return the time of the last update" do
      expect(subject.last_updated).to be == timestamp
    end
  end

  describe "#check_gem" do
    let(:gem) do
      Gem::Specification.new do |s|
        s.name    = 'actionpack'
        s.version = '3.1.9'
      end
    end

    context "when given a block" do
      it "should yield every advisory effecting the gem" do
        advisories = []

        subject.check_gem(gem) do |advisory|
          advisories << advisory
        end

        advisories.should_not be_empty
        advisories.all? { |advisory|
          advisory.kind_of?(Bundler::Audit::Advisory)
        }.should be_true
      end
    end

    context "when given no block" do
      it "should return an Enumerator" do
        subject.check_gem(gem).should be_kind_of(Enumerable)
      end
    end
  end

  describe "#size" do
    it "should return > 0" do
      expect(subject.size).to be > 0
    end
  end

  describe "#advisories" do
    let(:glob) { File.join(subject.path,'gems','*','*.yml') }

    it "should return a list of all advisories" do
      expect(subject.advisories.map(&:path)).to eq Dir[glob]
    end
  end

  describe "#to_s" do
    it "should return the Database path" do
      subject.to_s.should == subject.path
    end
  end

  describe "#inspect" do
    it "should produce a Ruby-ish instance descriptor" do
      expect(subject.inspect).to eq("#<Bundler::Audit::Database:#{subject.path}>")
    end
  end
end
