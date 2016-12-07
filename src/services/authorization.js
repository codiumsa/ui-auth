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
       **/
      hasPermission: function (permission, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrent();
        var permissions = [];

        if (user) {
          permissions = user.permissions || [];
        }
        return permissions.indexOf(permission.trim()) >= 0;
      },

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

      hasAnyPermissions: function (permissions, userToCheck) {
        var self = this;
        return _.some(permissions, function (p) {
          return self.hasPermission(p, userToCheck);
        });
      },

      hasRol: function (rol, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrentUser();
        var rols = [];

        if (user) {
          rols = user.rols || [];
        }
        return rols.indexOf(rol.trim()) >= 0;
      },

      principal: function () {
        return Authorization.get({ action: 'principal' }).$promise;
      },

      // TODO: ver como implementar esto
      // setupCredentials: function (username, requestToken, accessToken, callback) {
      //   var AuthParams = {
      //     username: username,
      //     requestToken: requestToken,
      //     accessToken: accessToken
      //   };

      //   $rootScope.AuthParams = AuthParams;
      //   localStorage.setItem(Config.authParamsKey, JSON.stringify(AuthParams));
      //   $http.defaults.headers.common.Authorization = 'Bearer ' + accessToken;
      //   // cargamos los permisos del usuario
      //   this.principal().then(function (response) {
      //     AuthParams.permissions = response.permisos;
      //     AuthParams.rols = response.roles;
      //     AuthParams.stamp = response.stamp;
      //     localStorage.setItem(Config.authParamsKey, JSON.stringify(AuthParams));
      //     callback(AuthParams);
      //   });
      // },

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
