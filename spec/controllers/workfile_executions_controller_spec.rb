require 'spec_helper'

describe WorkfileExecutionsController do
  let(:workspace) { workspaces(:public) }
  let(:workspace_member) { users(:the_collaborator) }
  let(:workfile) { workfiles(:public) }
  let(:archived_workspace) { workspaces(:archived) }
  let(:archived_workfile) { workfiles(:archived) }
  let(:sql) { "Select something from somewhere" }
  let(:check_id) { '12345' }
  let(:default_row_limit) { 500 }

  describe "#create" do
    it_behaves_like "an action that requires authentication", :post, :create, :workfile_id => '-1'

    context "as a member of the workspace" do
      before do
        log_in workspace_member
        stub.proxy(ChorusConfig.instance).[](anything)
        stub(ChorusConfig.instance).[]('default_preview_row_limit') { default_row_limit }
      end

      it "executes the sql with the check_id and default row limit" do
        sandbox = workspace.sandbox
        mock(SqlExecutor).execute_sql(sandbox, sandbox.account_for_user!(workspace_member), check_id, sql, hash_including(:limit => default_row_limit)) {
          SqlResult.new
        }
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id
      end

      it "uses the specified row limit if one is given" do
        mock(SqlExecutor).execute_sql(anything, anything, anything, anything, hash_including(:limit => 123)) { SqlResult.new }
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id, :num_of_rows => 123
      end

      it "sets the execution schema of the workfile" do
        workfile.execution_schema.should_not == workspace.sandbox
        stub(SqlExecutor).execute_sql { SqlResult.new }
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id
        workfile.reload.execution_schema.should == workspace.sandbox
      end

      it "uses the presenter for SqlResult" do
        stub(SqlExecutor).execute_sql { SqlResult.new }
        mock_present { |model| model.should be_a SqlResult }
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id
      end
    end

    it "uses authorization" do
      log_in workspace_member
      mock(subject).authorize! :can_edit_sub_objects, workspace
      post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id
    end

    it "returns an error if no check_id is given" do
      log_in workspace_member
      post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql
      response.code.should == '422'
      decoded = JSON.parse(response.body)
      decoded['errors']['fields']['check_id'].should have_key('BLANK')
    end

    context "with an archived workspace" do
      it "responds with invalid record response" do
        log_in workspace_member
        post :create, :workfile_id => archived_workfile.id, :schema_id => archived_workspace.sandbox.id, :sql => sql, :check_id => check_id
        response.code.should == "422"

        decoded = JSON.parse(response.body)
        decoded['errors']['fields']['workspace'].should have_key('ARCHIVED')
      end
    end

    context "when downloading the results" do
      let(:sql_result) {
        SqlResult.new.tap{ |result|
          result.add_column("a", "string")
          result.add_column("b", "string")
          result.add_column("c", "string")
          result.add_row([1,2,3])
          result.add_row([4,5,6])
          result.add_row([7,8,9])
        }
      }
      let(:user) { users(:owner) }
      before do
        log_in user

        mock.proxy(SqlStreamer).new(workspace.sandbox, sql, user, anything) { |streamer|
          mock(streamer).enum { 'response' }
        }
      end

      it "sets content disposition: attachment" do
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id, :download => true, :file_name => "some"
        response.headers['Content-Disposition'].should include("attachment")
        response.headers['Content-Disposition'].should include('filename=some.csv')
        response.headers['Content-Type'].should == 'text/csv'
      end

      it "returns the streamer response" do
        post :create, :workfile_id => workfile.id, :schema_id => workspace.sandbox.id, :sql => sql, :check_id => check_id, :download => true, :file_name => "some"
        response.body.should == 'response'
      end
    end

    describe "rspec fixtures", :database_integration do
      let(:schema) { GpdbSchema.find_by_name!('test_schema') }
      before do
        log_in users(:admin)
      end

      generate_fixture "workfileExecutionResults.json" do
        post :create, :workfile_id => workfile.id, :schema_id => schema.id, :sql => 'select * from base_table1', :check_id => check_id
      end

      generate_fixture "workfileExecutionResultsWithWarning.json" do
        post :create, :workfile_id => workfile.id, :schema_id => schema.id, :sql => 'create table table_with_warnings (id INT PRIMARY KEY); select * from base_table1', :check_id => check_id
      end

      generate_fixture "workfileExecutionResultsEmpty.json" do
        post :create, :workfile_id => workfile.id, :schema_id => schema.id, :sql => '', :check_id => check_id
      end

      generate_fixture "workfileExecutionError.json" do
        post :create, :workfile_id => workfile.id, :schema_id => schema.id, :sql => 'select hippopotamus', :check_id => check_id
        response.code.should == "422"
      end

      after do
        account = schema.account_for_user!(users(:admin))
        schema.with_gpdb_connection(account) do |connection|
          connection.exec_query("DROP TABLE IF EXISTS table_with_warnings")
        end
      end
    end
  end

  describe "#destroy" do
    before do
      log_in workspace_member
    end

    it "cancels the query for the given id" do
      sandbox = workspace.sandbox
      mock(SqlExecutor).cancel_query(sandbox, sandbox.account_for_user!(workspace_member), check_id)
      delete :destroy, :workfile_id => workfile.id, :id => check_id, :schema_id => sandbox.id
      response.should be_success
    end

    it "returns an error if no check_id is given" do
      delete :destroy, :workfile_id => workfile.id, :id => '', :schema_id => workspace.sandbox.id
      response.code.should == '422'
      decoded = JSON.parse(response.body)
      decoded['errors']['fields']['check_id'].should have_key('BLANK')
    end

    context "with an archived workspace" do
      it "responds with invalid record response" do
        delete :destroy, :workfile_id => archived_workfile.id, :id => check_id, :schema_id => archived_workspace.sandbox.id
        response.code.should == "422"

        decoded = JSON.parse(response.body)
        decoded['errors']['fields']['workspace'].should have_key('ARCHIVED')
      end
    end
  end
end
