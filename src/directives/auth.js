(function() {
  'use strict';

  /**
   * Directiva que se encarga de mostrar/ocultar elementos del DOM en base
   * a los permisos que posee el usuario que ha iniciado sesion.
   *
   * atributos disponibles:
   *  - when-login: hide | show, permite ocultar o mostrar el elemento si el usuario inicio sesion.
   *  - permissions: lista de permisos que indican si el elemento se debe mostrar o no.
   *  - requires-login: indica si para mostrar el elemento, el usuario debe iniciar sesion
   *  - some-permissions: lista de permisos. El elmento se muestra o no, si al menos un permiso se encuentra.
   *
   * @ngdoc directive
   * @name ui-auth.directives:auth
   * @description
   * # auth
   */
  angular
    .module('ui.auth.directives')
    .directive('auth', auth);

  auth.$inject = ['AuthenticationService', 'AuthorizationService'];

  function auth(AuthenticationService, AuthorizationService) {

    return {
      restrict: 'A',
      scope: {
        // expresion que se evalua a un array de strings, o un string donde los valores se separan por comas.
        somePermissions: '=',
        // expresion que se evalua a un array de strings, o un string donde los valores se separan por comas.
        permissions: '='
      },
      link: function(scope, element, attrs) {
        var requiresLogin = scope.permissions !== undefined || scope.somePermissions !== undefined || attrs.requiresLogin !== undefined;
        var permissions;
        var loggedIn = AuthenticationService.isLoggedIn();
        var remove = requiresLogin && !loggedIn;
        var somePermissions;

        if (attrs.whenLogin) {
          remove = loggedIn ? attrs.whenLogin === 'hide' : attrs.whenLogin === 'show';
        }

        if (scope.permissions) {
          permissions = scope.permissions;

          if (!angular.isArray(permissions)) {
            permissions = scope.permissions.split(',');
          }
        }

        if (permissions) {
          remove = !AuthorizationService.hasPermissions(permissions);
        }

        if (scope.somePermissions) {
          somePermissions = scope.somePermissions;

          if (!angular.isArray(somePermissions)) {
            somePermissions = scope.somePermissions.split(',');
          }
          remove = !AuthorizationService.hasSomePermissions(somePermissions);
        }

        if (remove) {
          element.remove();
        }
      }
    };
  }
}());
