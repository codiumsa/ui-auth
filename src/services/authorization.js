(function() {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.Authorization
   * @description
   * # Authorization
   * Service in the ui.auth.
   */
  angular
    .module('ui.auth.services')
    .factory('AuthorizationService', AuthorizationService);

  AuthorizationService.$inject = ['$resource', 'AuthConfig', '$injector'];

  function AuthorizationService($resource, AuthConfig, $injector) {
    var Authorization = $resource(AuthConfig.serverURL + '/authorization/:action', { action: '@action' });

    return {
      /**
       * Retorna true si el usuario actual de la aplicación posee el permiso dado como
       * parámetro.
       *
       * @param {string} permission - El permiso a corroborar
       * @returns {boolean}
       **/
      hasPermission: function(permission) {
        const CurrentUserService = $injector.get('CurrentUserService');
        const permissions = CurrentUserService.getPermissions();
        return permissions.indexOf(permission.trim()) >= 0;
      },

      /**
       * Verifica si el usuario dado como parametro posee los permisos en cuestión.
       *
       * @param {string[]} permissions - lista de permisos a controlar
       * @returns {boolean}
       */
      hasPermissions: function(permissions) {
        var authorized = true;

        for (var i = 0; i < permissions.length; i++) {
          if (!this.hasPermission(permissions[i])) {
            authorized = false;
            break;
          }
        }
        return authorized;
      },

      /**
       * Helper para determinar si el usuario posee al menos un permiso.
       *
       * @param {string[]} permissions - lista de permisos
       * @returns {boolean}
       */
      hasSomePermissions: function(permissions) {
        return _.some(permissions, (p) => this.hasPermission(p));
      },

      /**
       * Verifica si el usuario posee el rol dado como parámetro.
       *
       * @param {string} rol - Rol a controlar
       * @returns {boolean}
       */
      hasRol: function(rol) {
        const CurrentUserService = $injector.get('CurrentUserService');
        const rols = CurrentUserService.getRols();
        return rols.indexOf(rol.trim()) >= 0;
      },

      /**
       * Helper para determinar si el user actual esta o no autorizado para realizar
       * una acción en particular.
       *
       * @param {boolean} loginRequired - Indica si la acción a realizar requiere que el usuario esté autenticado.
       * @param {string[]} requiredPermissions - Lista de permisos solicitados por la acción.
       * @returns {string} -  loginRequired | notAuthorized | authorized
       */
      authorize: function(loginRequired, requiredPermissions) {
        const CurrentUserService = $injector.get('CurrentUserService');

        if (loginRequired === true && user === undefined) {
          return this.enums.LOGIN_REQUIRED;
        } else if ((loginRequired && CurrentUserService.isLoggedIn()) &&
          (requiredPermissions === undefined || requiredPermissions.length === 0)) {
          return this.enums.AUTHORIZED;
        } else if (requiredPermissions) {
          var isAuthorized = this.hasPermissions(requiredPermissions);
          return isAuthorized ? this.enums.AUTHORIZED : this.enums.NOT_AUTHORIZED;
        }
      },

      enums: {
        LOGIN_REQUIRED: 'loginRequired',
        NOT_AUTHORIZED: 'notAuthorized',
        AUTHORIZED: 'authorized'
      }
    };
  }
}());
