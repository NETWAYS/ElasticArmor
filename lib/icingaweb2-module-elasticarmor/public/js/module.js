(function(Icinga) {

    var ElasticArmor = function(module) {
        this.module = module;

        this.initialize();

        this.includeValue = null;
        this.excludeValue = null;

        this.module.icinga.logger.debug('ElasticArmor module loaded');
    };

    ElasticArmor.prototype = {

        initialize: function()
        {
            /**
             * Tell Icinga about our event handlers
             */
            this.module.on('rendered', this.onRendered);
            this.module.on('keyup', 'form#elasticarmor_restriction_form input.include', this.onPatternChange);
            this.module.on('keyup', 'form#elasticarmor_restriction_form input.exclude', this.onPatternChange);

            this.module.icinga.logger.debug('ElasticArmor module initialized');
        },

        onRendered: function(event) {
            var self = this;
            var $restrictionForm = $('form#elasticarmor_restriction_form');

            if (! $restrictionForm.length) {
                self.includeValue = null;
                self.excludeValue = null;
            } else {
                var $discovery = $('div#discovery', $restrictionForm);
                var $include = $('input.include', $restrictionForm);
                var $exclude = $('input.exclude', $restrictionForm);

                if (! $discovery.hasClass('toggled') && $include.val() !== '') {
                    $discovery.addClass('toggled');
                    self.includeValue = $include.val();
                    self.excludeValue = $exclude.val();
                    self.runDiscovery().forceFocus = $include;
                } else {
                    $include.next().removeClass('active');
                    $exclude.next().removeClass('active');
                }
            }
        },

        onPatternChange: function(event) {
            var self = this;
            var $input = $(event.currentTarget);
            var $include = $('form#elasticarmor_restriction_form input.include');
            var $exclude = $('form#elasticarmor_restriction_form input.exclude');

            if ($include.val() === self.includeValue && $exclude.val() === self.excludeValue) {
                return;
            } else {
                self.includeValue = $include.val();
                self.excludeValue = $exclude.val();
            }

            var $discovery = $('div#discovery');
            if (! $discovery.hasClass('toggled')) {
                $discovery.addClass('toggled');
            }

            if ($input.next().hasClass('spinner')) {
                $input.next().addClass('active');
            }

            self.runDiscovery().forceFocus = $input;
        },

        runDiscovery: function() {
            var self = this;
            var req = self.module.icinga.loader.loadUrl(
                self.module.icinga.utils.addUrlParams(
                    $('input[name=discover_url]').val(),
                    {
                        'include': self.includeValue,
                        'exclude': self.excludeValue
                    }
                ),
                $('div#discovery')
            );
            req.addToHistory = false;
            return req;
        }
    };

    Icinga.availableModules.elasticarmor = ElasticArmor;

}(Icinga));
