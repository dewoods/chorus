require 'spec_helper'

describe TagPresenter, :type => :view do
  let(:presenter)  { TagPresenter.new(tag, view) }
  let(:tag) { ActsAsTaggableOn::Tag.where(:name => "alpha").first }

  describe "#to_hash" do
    let(:hash) { presenter.to_hash }

    it "includes the id" do
      hash[:id].should == tag.id
    end

    it "includes the name" do
      hash[:name].should == 'alpha'
    end

    it "includes a count" do
      hash[:count].should == 1
    end
  end
end
