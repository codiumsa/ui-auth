(function () {
  'use strict';

  /**
   * Provider para configuracion ui.auth.
   *
   * @ngdoc service
   * @name ui.auth.AuthConfigProvider
   * @description
   * # AuthConfigProvider
   */
  angular.module('ui.auth')
    .provider('AuthConfigProvider', function () {

      var options = {};

      this.config = function (opt) {
        angular.extend(options, opt);
      };

      this.$get = [function () {
        return options;
      }];
    });
} ());
