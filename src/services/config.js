(function () {
  'use strict';

  /**
   * Provider para configuracion ui.auth.
   *
   * @ngdoc service
   * @name ui.auth.AuthConfig
   * @description
   * # AuthConfig
   */
  angular.module('ui.auth')
    .provider('AuthConfig', function () {

      var options = {};

      this.config = function (opt) {
        angular.extend(options, opt);
      };

      this.$get = [function () {
        return options;
      }];
    });
} ());
