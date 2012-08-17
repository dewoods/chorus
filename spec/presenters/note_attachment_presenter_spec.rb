require 'spec_helper'

describe NoteAttachmentPresenter, :type => :view do

  let(:note_attachment) { NoteAttachment.first }
  let(:presenter) { NoteAttachmentPresenter.new(note_attachment, view) }

  describe "#to_hash" do
    let(:hash) { presenter.to_hash }

    it "includes the right keys" do
      hash.should have_key(:id)
      hash.should have_key(:name)
      hash.should have_key(:timestamp)
      hash.should have_key(:entity_type)
      hash.should have_key(:type)
    end

    context "when the attachment is an image" do
      let(:note_attachment) { note_attachments(:image) }
      it "should have an icon url" do
        hash[:icon_url].should be_present
      end

      context "when the attachment is not an image" do
        let(:note_attachment) { note_attachments(:sql) }
        it "should have a null icon url" do
          hash[:icon_url].should be_nil
        end
      end
    end
  end
end
