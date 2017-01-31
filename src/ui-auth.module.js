(function() {
  'use strict';

  angular.module('ui.auth.services', []);

  angular.module('ui.auth.directives', ['ui.auth.services']);

  angular.module('ui.auth', [
    'ngResource',
    'ui.auth.services',
    'ui.auth.directives'
  ]);
}());
