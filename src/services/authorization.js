(function () {
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
    .service('AuthorizationService', AuthorizationService);

  AuthorizationService.$inject = ['$resource', 'AuthenticationService', 'AuthConfig'];

  function AuthorizationService($resource, AuthenticationService, AuthConfig) {
    var Authorization = $resource(AuthConfig.serverURL + '/authorization/:action',
      { action: '@action' });

    return {
      /**
       * Retorna true si el usuario actual de la aplicación posee el permiso dado como
       * parámetro.
       *
       * @param {string} permission - El permiso a corroborar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       **/
      hasPermission: function (permission, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrent();
        var permissions = [];

        if (user) {
          permissions = user.permissions || [];
        }
        return permissions.indexOf(permission.trim()) >= 0;
      },

      /**
       * Verifica si el usuario dado como parametro posee los permisos en cuestion.
       *
       * @param {string[]} permissions - lista de permisos a controlar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
      hasPermissions: function (permissions, userToCheck) {
        var self = this;
        var authorized = true;

        for (var i = 0; i < permissions.length; i++) {

          if (!self.hasPermission(permissions[i], userToCheck)) {
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
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
      hasAnyPermissions: function (permissions, userToCheck) {
        var self = this;
        return _.some(permissions, function (p) {
          return self.hasPermission(p, userToCheck);
        });
      },

      /**
       * Verifica si el usuario posee el rol dado como parámetro.
       *
       * @param {string} rol - Rol a controlar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
      hasRol: function (rol, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrent();
        var rols = [];

        if (user) {
          rols = user.rols || [];
        }
        return rols.indexOf(rol.trim()) >= 0;
      },

      /**
       * Metodo que se encarga de recuperar del servidor los permisos que posee el usuario
       * actual.
       *
       * @returns {Promise}
       */
      principal: function () {
        return Authorization.get({ action: 'principal' }).$promise;
      },

      /**
       * Helper para determinar si el user actual esta o no autorizado para realizar
       * un acción en particular.
       *
       * @param {boolean} loginRequired - Indica si la acción a realizar requiere que el usuario esté autenticado.
       * @param {string[]} requiredPermissions - Lista de permisos solicitados por la acción.
       * @returns {string} -  loginRequired | notAuthorized | authorized
       */
      authorize: function (loginRequired, requiredPermissions) {
        var user = AuthenticationService.getCurrentUser();

        if (loginRequired === true && user === undefined) {
          return this.enums.LOGIN_REQUIRED;
        } else if ((loginRequired && user !== undefined) &&
          (requiredPermissions === undefined || requiredPermissions.length === 0)) {
          return this.enums.AUTHORIZED;
        } else if (requiredPermissions) {
          var isAuthorized = this.hasPermissions(requiredPermissions, user);
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
} ());
