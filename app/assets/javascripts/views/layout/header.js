chorus.views.Header = chorus.views.Base.extend({
    constructorName: "HeaderView",
    templateName: "header",
    events: {
        "click .username a": "togglePopupUsername",
        "click a.notifications": "togglePopupNotifications",
        "click .gear a": "togglePopupGear",
        "click .type_ahead_result a": "clearSearch",
        "submit .search form": "startSearch",
        "keydown .search input": "searchKeyPressed"
    },

    subviews: {
        ".popup_notifications ul": "notificationList",
        ".type_ahead_result": "typeAheadView"
    },

    setup: function() {
        this.session = chorus.session;
        this.unreadNotifications = new chorus.collections.NotificationSet([], { type: 'unread' });
        this.notifications = new chorus.collections.NotificationSet();
        this.notifications.per_page = 5;

        this.typeAheadView = new chorus.views.TypeAheadSearch();

        this.notificationList = new chorus.views.NotificationList({
            collection: new chorus.collections.NotificationSet()
        });

        this.listenTo(this.unreadNotifications, "loaded", this.updateNotifications);
        this.listenTo(this.notifications, "loaded", this.updateNotifications);

        this.unreadNotifications.fetchAll();
        this.notifications.fetch();

        if (chorus.isDevMode()) {
            this.users = new chorus.collections.UserSet();
            this.users.fetchAll();
        }

        this.subscribePageEvent("notification:deleted", this.refreshNotifications);
    },

    disableSearch: function() {
        this.typeAheadView.disableSearch();
    },

    updateNotifications: function() {
        if (this.notifications.loaded && this.unreadNotifications.loaded) {
            this.notificationList.collection.reset(this.unreadNotifications.models, { silent: true });
            var numberToAdd = (5 - this.unreadNotifications.length);
            if (numberToAdd > 0) {
                this.notificationList.collection.add(this.notifications.chain().reject(
                    function(model) {
                        return !!this.unreadNotifications.get(model.get("id"));
                    }, this).first(numberToAdd).value());
            }

            this.notificationList.collection.loaded = true;
            this.render();
        }
    },

    postRender: function() {
        this.$(".search input").unbind("textchange").bind("textchange", _.bind(_.throttle(this.displayResult, 500), this));
        chorus.addClearButton(this.$(".search input"));

        if (chorus.isDevMode()) {
            this.addFastUserToggle();
        }
        this.modifyTypeAheadSearchLength();
    },

    addFastUserToggle: function() {
        var self = this;
        var session = chorus.session;

        function switchUser(username) {
            session.requestLogout(function(res) {
                // log back in as new user
                self.listenTo(session, "saved", _.bind(chorus.router.reload, chorus.router));
                self.listenTo(session, "saveFailed", function() { session.trigger("needsLogin"); });
                session.save({username: username, password: "secret"});
                session.updateToken(res);
            });
        }

        function addDropdown() {
            $('select.switch_user').remove();
            var $select = $("<select class='switch_user'></select>");

            $select.append("<option>Switch to user..</option>");
            self.users.each(function(user) {
                $select.append("<option value=" + Handlebars.Utils.escapeExpression(user.get("username")) + ">" + Handlebars.Utils.escapeExpression(user.displayName()) + "</option>");
            });

            $("body").append($select);
            $select.unbind("change").bind("change", function() {
                switchUser($(this).val());
            });
        }

        this.listenTo(this.users, "loaded", addDropdown);
    },

    searchKeyPressed: function(event) {
        this.typeAheadView.handleKeyEvent(event);
    },

    displayResult: function() {
        var query = this.$(".search input").val();
        if (this.typeAheadView.searchFor(query)) {
            if ( this.typeAheadView.$el.hasClass("hidden") ) {
                chorus.PopupMenu.toggle(this, this.typeAheadView.el);
            }
        } else {
            chorus.PopupMenu.close(this);
        }
    },

    clearSearch: function() {
        this.$(".search input").val('');
        this.displayResult();
    },

    additionalContext: function(ctx) {
        this.requiredResources.reset();
        var user = this.session.user();

        return _.extend(ctx, this.session.attributes, {
            notifications: this.unreadNotifications,
            fullName: user && user.displayName(),
            displayName: user && user.displayShortName(),
            userUrl: user && user.showUrl(),
            brandingLogo: chorus.models.Config.instance().get("brandingLogo")
        });
    },

    refreshNotifications: function() {
        this.notifications.loaded = false;
        this.unreadNotifications.loaded = false;
        this.requiredResources.add([this.unreadNotifications, this.notifications]);
        this.notifications.fetch();
        this.unreadNotifications.fetchAll();
    },

    togglePopupNotifications: function(e) {
        var beingShown = this.$(".menu.popup_notifications").hasClass("hidden");

        chorus.PopupMenu.toggle(this, ".menu.popup_notifications", e);

        if (beingShown) {
            this.unreadNotifications.markAllRead({ success: _.bind(this.clearNotificationCount, this) });
            this.notificationList.show();
        } else {
            this.unreadNotifications.each(function(model) {
                model.set({ unread: false }, { silent: true });
            });
            this.notificationList.collection.trigger("reset");
        }
    },

    clearNotificationCount: function() {
        this.$("a.notifications").text("0").addClass("empty");
    },

    togglePopupUsername: function(e) {
        chorus.PopupMenu.toggle(this, ".menu.popup_username", e);
    },

    togglePopupGear: function(e) {
        chorus.PopupMenu.toggle(this, ".menu.popup_gear", e);
    },

    modifyTypeAheadSearchLength: function() {
        if(!_.isEmpty($('.left')) && !_.isEmpty($('.type_ahead_search'))) {
            this.$('.type_ahead_search').css('left', (this.$('.left').width() + parseInt($('.search').css('padding-left'), 10) + 1) + "px");
        }
    },

    startSearch: function(e) {
        e.preventDefault();
        var query = this.$(".search input:text").val();
        if (query.length > 0) {
            var search = new chorus.models.SearchResult({
                workspaceId: this.workspaceId,
                query: query
            });
            chorus.router.navigate(search.showUrl());
        }
    }
});
