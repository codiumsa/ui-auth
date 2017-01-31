(function() {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.Authentication
   * @description
   * # Authentication
   * Service in the ui.auth.
   */
  angular
    .module('ui.auth.services')
    .factory('AuthenticationService', AuthenticationService);

  AuthenticationService.$inject = ['$resource', 'AuthConfig', '$injector'];

  function AuthenticationService($resource, AuthConfig, $injector) {
    var Authentication = $resource(AuthConfig.serverURL + '/oauth/token');
    let refreshing = false;

    return {
      login,
      refresh,
      fetchCurrentUser,
      isLoggedIn
    };

    /**
     * Autenticacion basada en username/password
     * 
     * @param {string} username
     * @param {string} password
     */
    function login(username, password) {
      var auth = new Authentication({
        grantType: 'password',
        username: username,
        password: password
      });
      var rsp = auth.$save();
      rsp.then(loginSuccess);
      return rsp;
    }

    /**
     * Renovación de access_token
     * 
     * @param {string} refreshToken
     */
    function refresh(refreshToken) {

      if (refreshing) {
        return;
      }
      refreshing = true;
      var auth = new Authentication({
        grantType: 'refresh_token',
        refreshToken: refreshToken
      });
      var rsp = auth.$save();
      rsp.then((data) => {
        refreshing = false;
        return data;
      })
      rsp.then(loginSuccess);
      return rsp;
    }

    /**
     * Retorna el usuario actual.
     *
     * @returns {object} Promise que se puede utilizar para recuperar el estado actual.
     */
    function fetchCurrentUser() {
      let resource = $resource(AuthConfig.serverURL + '/oauth/user');
      return resource.get().$promise;
    }

    /**
     * @returns {boolean} Retorna true, si se ha iniciado sesión. False en caso contrario.
     */
    function isLoggedIn() {
      const CurrentUserService = $injector.get('CurrentUserService');
      return CurrentUserService.isLoggedIn();
    }

    /**
     * Login success callback para registrar en el localStorage los
     * datos de autenticación.
     *
     * @param {object} data - datos de autenticacion
     * @private
     */
    function loginSuccess(data) {
      localStorage.setItem(AuthConfig.preffix, JSON.stringify(data));
    }
  }
}());
