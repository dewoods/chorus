describe("chorus.models.DynamicInstance", function() {
    it("should return a gpdb instance when the entity_type is gpdb_instance", function() {
        var model = new chorus.models.DynamicInstance({entityType: "gpdb_instance"});
        expect(model).toBeA(chorus.models.GpdbInstance);
    });

    it("should return a hadoop instance when the entity_type is hadoop_instance", function() {
        var model = new chorus.models.DynamicInstance({entityType: "hadoop_instance"});
        expect(model).toBeA(chorus.models.HadoopInstance);
    });

    it("should return a gnip instance when the entity_type is gnip_instance", function() {
        var model = new chorus.models.DynamicInstance({entityType: "gnip_instance"});
        expect(model).toBeA(chorus.models.GnipInstance);
    });
});