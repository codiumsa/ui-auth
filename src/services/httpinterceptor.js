(function() {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.HttpInterceptor
   * @description
   * # HttpInterceptor
   * Factory in the ui.auth.
   */
  angular
    .module('ui.auth.services')
    .factory('HttpInterceptor', HttpInterceptor);

  HttpInterceptor.$inject = ['$q', '$location', '$injector'];

  function HttpInterceptor($q, $location, $injector) {

    return {
      request: function(config) {
        let TokenService = $injector.get('TokenService');
        const token = TokenService.getToken();

        if (token) {
          config.headers.Authorization = 'Bearer ' + token;
        }
        config.headers['Content-Type'] = 'application/json';
        return config;
      },

      requestError: function(rejection) {
        let AuthConfig = $injector.get('AuthConfig');

        if (rejection.status === 401) {
          $location.path(AuthConfig.loginPath);
        }
        return $q.reject(rejection);
      },

      response: function(response) {
        return response;
      },

      responseError: function(rejection) {
        let AuthConfig = $injector.get('AuthConfig');
        var $window = $injector.get('$window');

        // verificamos si la renovación del access token falló
        if (rejection.status === 500 && rejection.config.method === 'POST' &&
          rejection.config.url === `${AuthConfig.serverURL}/token`) {
          $location.path(AuthConfig.loginPath);
          $window.location.reload();
        }

        if (rejection.status === 401) {
          // verificamos si fue un error de autorización
          if (rejection.data && rejection.data.code === 403) {
            // TODO: mandar el error de autorización en un evento, para poder manejar en el cliente.
            $location.path('/');
            return $q.reject(rejection);
          }

          if ($location.path() === AuthConfig.loginPath) {
            return $q.reject(rejection);
          }
          var deferred = $q.defer();
          var AuthenticationService = $injector.get('AuthenticationService');
          var TokenService = $injector.get('TokenService');
          var rsp = AuthenticationService.refresh(TokenService.getRefreshToken());
          rsp.then(deferred.resolve, deferred.reject);
          return deferred.promise.then(function() {
            return $http(rejection.config);
          });
        }
        return $q.reject(rejection);
      }
    };
  }
}());
