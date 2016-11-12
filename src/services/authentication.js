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

AuthenticationService.$injec = ['$resource', '$rootScope', '$http', 'Config'];

function AuthenticationService($resource, $rootScope, $http, Config) {
  var Authentication = $resource(Config.serverURL + '/:action', {action: '@action'});

  return {
    login: function (username, password) {
      var auth = new Authentication({username: username, password: password});
      return auth.$save({action: 'login'});
    },

    token: function (authParams) {
      var auth = new Authentication({
        username: authParams.username,
        accessToken: authParams.accessToken
      });
      return auth.$save({action: 'token'});
    },

    logout: function () {
      var authParams = this.getCurrentUser();
      var auth = new Authentication({
        username: authParams.username,
        accessToken: authParams.accessToken
      });
      $rootScope.AuthParams = {};
      localStorage.removeItem(Config.authParamsKey);
      return auth.$save({action: 'logout'});
    },

    getCurrentUser: function () {
      var user = $rootScope.AuthParams;

      if (!user || Object.keys(user).length === 0) {
        user = JSON.parse(localStorage.getItem(Config.authParamsKey)) || undefined;

        if (user) {
          $http.defaults.headers.common.Authorization = 'Bearer ' + user.accessToken;
        }
      }
      return user;
    },

    isLoggedIn: function() {
      var user = this.getCurrentUser();
      return user && user.accessToken !== undefined;
    }
  };
}

}());
