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
    .service('AuthenticationService', AuthenticationService);

  AuthenticationService.$injec = ['$resource', 'AuthConfig'];

  function AuthenticationService($resource, AuthConfig) {
    var Authentication = $resource(AuthConfig.serverURL + '/oauth/token');

    return {
      login: login,
      refresh: refresh
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
      var auth = new Authentication({
        grantType: 'refresh_token',
        refreshToken: refreshToken
      });
      var rsp = auth.$save();
      rsp.then(loginSuccess);
      return rsp;
    }

    /**
     * Login success callback para registrar en el localStorage los
     * datos de autenticación.
     *
     * @param {object} data - datos de autenticacion
     */
    function loginSuccess(data) {
      localStorage.setItem(AuthConfig.preffix, JSON.stringify(data));
    }

    /**
     * Retorna el usuario actual.
     *
     * @returns {object} Promise que se puede utilizar para recuperar el estado actual.
     */
    function getCurrentUser() {
      let resource = $resource(AuthConfig.serverURL + '/oauth/user');
      return resource.get().$promise;
    }
  }
}());
