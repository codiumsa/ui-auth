(function() {
  var app = angular
    .module('uiAuthSample', ['ui.auth']);

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
    var token = true;

    return {
      getToken: function() {
        return token;
      },

      setToken: function(newToken) {
        token = newToken;
      }
    }
  }

  app.factory('CurrentUserService', CurrentUserService);

  CurrentUserService.$inject = ['TokenService'];

  function CurrentUserService(TokenService) {
    return {
      getRols: function() {
        return ['admin'];
      },

      getPermissions: function() {
        return ['read', 'create', 'edit', 'delete'];
      },

      isLoggedIn: function() {
        return TokenService.getToken();
      }
    };
  }

  //// controller 
  app.controller('SampleController', SampleController);
  SampleController.$inject = ['$http', '$scope', 'TokenService'];

  function SampleController($http, $scope, TokenService) {
    $scope.test = function() {
      $http({
        method: 'GET',
        url: 'https://jsonplaceholder.typicode.com/posts/1'
      }).then(function(data) {
        alert(JSON.stringify(data));
      });
    }

    $scope.login = function() {
      TokenService.setToken(true);
    };
  }
}());
