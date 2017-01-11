(function() {
  var app = angular
    .module('uiAuthSample', ['ui.auth', 'ui.auth.services', 'ui.auth.directives']);

  //// config
  app.config(config);
  config.$inject = ['AuthConfigProvider', '$httpProvider'];

  function config(AuthConfigProvider, $httpProvider) {
    AuthConfigProvider.config({
      serverURL: '/server',
      loginPath: '/login'
    });
    $httpProvider.interceptors.push('HttpInterceptor');
  }

  //// service
  app.factory('TokenService', TokenService);

  function TokenService() {
    return {
      getToken: function() {
        return '123456789';
      }
    }
  }

  //// controller 
  app.controller('SampleController', SampleController);
  SampleController.$inject = ['$http', '$scope'];

  function SampleController($http, $scope) {
    $scope.test = function() {
      $http({
        method: 'GET',
        url: 'https://jsonplaceholder.typicode.com/posts/1'
      }).then(function(data) {
        alert(JSON.stringify(data));
      });
    }
  }
}());