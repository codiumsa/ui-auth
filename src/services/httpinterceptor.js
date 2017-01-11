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
            //ngNotify.set(rejection.data.error, 'error');
            // TODO: mandar el error de autorización en un evento, para poder manejar en el cliente.
            $location.path('/');
            return $q.reject(rejection);
          }

          if ($location.path() === AuthConfig.loginPath) {
            return $q.reject(rejection);
          }

          // TODO: si el access_token expiró, renegociar con el backend.

          // var deferred = $q.defer();
          // var AuthenticationService = $injector.get('AuthenticationService');
          // var $http = $injector.get('$http');
          // console.log($rootScope.AuthParams);
          // var auth = AuthenticationService.token($rootScope.AuthParams);
          // auth.then(function(response) {
          //   $rootScope.AuthParams.accessToken = response.accessToken;
          //   localStorage.setItem(Config.authParamsKey, JSON.stringify($rootScope.AuthParams));
          //   $http.defaults.headers.common.Authorization = 'Bearer ' + response.accessToken;
          // }).then(deferred.resolve, deferred.reject);

          // return deferred.promise.then(function() {
          //   rejection.config.headers.Authorization = 'Bearer ' + $rootScope.AuthParams.accessToken;
          //   return $http(rejection.config);
          // });
        }
        return $q.reject(rejection);
      }
    };
  }
}());