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
      link: function(scope, element, attrs) {
        var requiresLogin = attrs.permissions !== undefined || attrs.requiresLogin !== undefined;
        var permissions;
        var loggedIn = AuthenticationService.isLoggedIn();
        var remove = requiresLogin && !loggedIn;
        var somePermissions;

        if (attrs.whenLogin) {
          remove = loggedIn ? attrs.whenLogin === 'hide' : attrs.whenLogin === 'show';
        }

        if (attrs.permissions) {
          permissions = attrs.permissions.split(',');
        }

        if (permissions) {
          remove = !AuthorizationService.hasPermissions(permissions);
        }

        if (attrs.somePermissions) {
          somePermissions = attrs.somePermissions.split(',');
          remove = !AuthorizationService.hasSomePermissions(somePermissions);
        }

        if (remove) {
          element.remove();
        }
      }
    };
  }
}());
