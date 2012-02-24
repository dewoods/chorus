chorus.models.SearchResult = chorus.models.Base.extend({
    urlTemplate: "search/global/",

    urlParams: function() {
        return {query: this.get("query")}
    },

    displayShortName:function (length) {
        length = length || 20;

        var name = this.get("query") || "";
        return (name.length < length) ? name : name.slice(0, length) + "...";
    },

    workfiles: function() {
        var workfiles = _.map(this.get("workfile").docs, function(workfileJson) {
            workfileJson.fileName = $.stripHtml(workfileJson.name);
            return new chorus.models.Workfile(workfileJson);
        });
        return new chorus.collections.WorkfileSet(workfiles);
    }
});
