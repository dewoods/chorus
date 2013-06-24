chorus.views.HdfsShowFileSidebar = chorus.views.Sidebar.extend({
    templateName: "hdfs_show_file_sidebar",
    constructorName: "HdfsShowFileSidebar",

    events: {
        "click a.external_table": "createExternalTable",
        "click a.add_note": "launchNotesNewDialog"
    },

    subviews:{
        '.tab_control': 'tabs'
    },

    setup: function() {
        this.tabs = new chorus.views.TabControl(["activity"]);
        this.tabs.activity && this.tabs.activity.collection.fetch();

        var activities = this.model.activities();
        activities.fetch();

        this.listenTo(activities, "changed", this.render);
        this.listenTo(activities, "reset", this.render);

        this.tabs.activity = new chorus.views.ActivityList({
            collection: activities,
            additionalClass: "sidebar",
            type: t("hdfs.file")
        });

        this.subscribePageEvent("csv_import:started", function() { activities.fetch(); });
    },

    additionalContext: function() {
        return {
            fileName: this.model.get("name"),
            entityId: this.model.id,
            lastUpdated: t("hdfs.last_updated", { when: Handlebars.helpers.relativeTimestamp(this.model.get('lastUpdatedStamp')) }),
            canCreateExternalTable: this.canCreateExternalTable()
        };
    },

    canCreateExternalTable: function() {
        return this.model.loaded && !this.model.get("isBinary") && !this.model.serverErrors;
    },

    createExternalTable: function(e) {
        e && e.preventDefault();

        var csvOptions = {
            tableName: this.model.get("name"),
            contents: this.model.get('contents')
        };
        
        var hdfsExternalTable = new chorus.models.HdfsExternalTable({
            hdfs_entry_id: this.model.get('id')
        });

        var dialog = new chorus.dialogs.CreateExternalTableFromHdfs({model: hdfsExternalTable, csvOptions: csvOptions});
        dialog.launchModal();
    },

    launchNotesNewDialog: function(e) {
        e && e.preventDefault();
        var dialogOptions = {
            pageModel: this.resource,
            entityId: this.resource.id,
            entityType: "hdfs_file",
            allowWorkspaceAttachments: false,
            displayEntityType: t("hdfs.file_lower")
        };

        var dialog = new chorus.dialogs.NotesNew(dialogOptions);
        dialog.launchModal();
    }
});