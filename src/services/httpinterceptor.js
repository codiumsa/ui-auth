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
  
HttpInterceptor.$inject = ['$q', '$location', '$rootScope', '$injector'];

function HttpInterceptor($q, $location, $rootScope, $injector) {
    
  // TODO: 
  // - deberia mandarse a la URL de login de forma generica o preconfigurada
  // - mejorar la asignaciond el header Autorizacion
  
  return {
    request: function(config) {

      if($location.path() !== '/ingresar' && $rootScope.AuthParams) {
        config.headers.Authorization = 'Bearer ' + $rootScope.AuthParams.accessToken;
      }
      return config;
    },

    requestError: function(rejection) {

      if(rejection.status === 401) {
        $location.path('/ingresar');
      }
      return $q.reject(rejection);
    },

    response: function(response) {
      return response;
    },

    responseError: function(rejection) {
      var ngNotify = $injector.get('ngNotify');
      var Config = $injector.get('Config');
      var $window = $injector.get('$window');

      if(rejection.status === 500 && rejection.config.method === 'POST' &&
         rejection.config.url.endsWith('rest/token')) {
           // error al renovar el access_token. Simplemente desloguear
          localStorage.removeItem(Config.authParamsKey);
          $location.path('/');
          $window.location.reload();     
      }

      if(rejection.status === 401) {
        if(rejection.data && rejection.data.code === 403) {
          // error de autorización
          ngNotify.set(rejection.data.error, 'error');
          $location.path('/');
          return $q.reject(rejection);
        }

        if($location.path() === '/ingresar') {
          return $q.reject(rejection);
        }

        var deferred = $q.defer();
        var AuthenticationService = $injector.get('AuthenticationService');
        var $http = $injector.get('$http');
        console.log($rootScope.AuthParams);
        var auth = AuthenticationService.token($rootScope.AuthParams);
        auth.then(function(response) {
          $rootScope.AuthParams.accessToken = response.accessToken;
          localStorage.setItem(Config.authParamsKey, JSON.stringify($rootScope.AuthParams));
          $http.defaults.headers.common.Authorization = 'Bearer ' + response.accessToken;
        }).then(deferred.resolve, deferred.reject);

        return deferred.promise.then(function() {
            rejection.config.headers.Authorization = 'Bearer ' + $rootScope.AuthParams.accessToken;
            return $http(rejection.config);
        });
      }
      return $q.reject(rejection);
    }
  };
}
}());
