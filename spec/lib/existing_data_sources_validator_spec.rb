require 'spec_helper'

def it_validates_duplicate(new_model, existing_model)
  it "returns false if a #{new_model.to_s.classify} is invalid" do
    FactoryGirl.create(new_model, :name => 'awesome_duplicate_name')
    FactoryGirl.build(existing_model, :name => 'awesome_duplicate_name').save(:validate => false)

    ExistingDataSourcesValidator.run(data_sources).should be_false
  end
end

describe ExistingDataSourcesValidator do
  before do
    stub(ExistingDataSourcesValidator).log
  end

  describe '.run' do
    let(:data_sources) { [GpdbDataSource, HadoopInstance, GnipInstance] }

    it "returns true if the data sources are all valid" do
      ExistingDataSourcesValidator.run(data_sources).should be_true
    end

    it_validates_duplicate(:gpdb_data_source, :gnip_instance)
    it_validates_duplicate(:hadoop_instance, :gpdb_data_source)
    it_validates_duplicate(:gnip_instance, :gnip_instance)

    it "doesn't validate tables that don't exist" do
      clazz = Class.new(ActiveRecord::Base) do
        table_name = 'non_existant_records'
      end

      ExistingDataSourcesValidator.run([clazz]).should be_true
    end
  end
end