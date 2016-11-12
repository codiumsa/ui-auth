(function() {
'use strict';

angular.module('ui.auth', ['ui']);
angular.module('ui.auth.directives', []);
angular.module('ui.auth.services', []);
}());
(function() {
'use strict';

/**
 * Directiva que se encarga de mostrar/ocultar elementos del DOM en base
 * a los permisos que posee el usuario que ha iniciado sesion.
 *
 * atributos disponibles:
 *  - when-login: hide | show, permite ocultar o mostrar el elemento si el usuario inicio sesion.
 *  - permissions: lista de permisos que indican si el elemento se debe mostrar o no.
 *  - requires-login: indica si para mostrar el elemento, el usuario debe iniciar sesion
 *
 * @ngdoc directive
 * @name ui-auth.directives:auth
 * @description
 * # auth
 */
angular
  .module('ui.auth.directives')
  .directive('auth', auth);

auth.$inject = ['AuthenticationService', 'AuthorizationService'];

function auth(AuthenticationService, AuthorizationService) {
  
  return {
    restrict: 'A',
    link: function postLink(scope, element, attrs) {
      var requiresLogin = attrs.permissions !== undefined || attrs.requiresLogin !== undefined;
      var permissions;
      var loggedIn = AuthenticationService.isLoggedIn();
      var remove = requiresLogin && !loggedIn;
      var anyPermissions;

      if(attrs.whenLogin) {
        remove = loggedIn ? attrs.whenLogin === 'hide' : attrs.whenLogin === 'show';
      }
      
      if(attrs.permissions) {
        permissions = attrs.permissions.split(',');
      }

      if(permissions) {
        remove = !AuthorizationService.hasPermissions(permissions);
      }
      
      if(attrs.anyPermissions) {
        anyPermissions = attrs.anyPermissions.split(',');
        remove = !AuthorizationService.hasAnyPermissions(anyPermissions);
      }

      if(remove) {
        element.remove();
      }
    }
  };
}
}());

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

(function() {
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
  
AuthorizationService.$inject = ['$rootScope', '$resource', '$http', 'AuthenticationService', 'Config'];

function AuthorizationService($rootScope, $resource, $http, AuthenticationService, Config) {
  var Authorization = $resource(Config.serverURL + '/authorization/:action',
    {action: '@action'});

  return {
    /**
     * Retorna true si el usuario actual de la aplicación posee el permiso dado como
     * parámetro.
     **/
    hasPermission: function (permission, userToCheck) {
      var user = userToCheck || AuthenticationService.getCurrentUser();
      var permissions = [];
      
      if (user) {
        permissions = user.permissions || [];
      }
      return permissions.indexOf(permission.trim()) >= 0;
    },

    hasPermissions: function(permissions, userToCheck) {
      var self = this;
      var authorized = true;
      
      for(var i = 0; i < permissions.length; i++){
        
        if(!self.hasPermission(permissions[i], userToCheck)){
          authorized = false;
          break;
        }
      }
      return authorized;
    },
    
    hasAnyPermissions: function(permissions, userToCheck) {
      var self = this;
      return _.some(permissions, function(p) {
        return self.hasPermission(p, userToCheck);
      });
    },

    hasRol: function(rol, userToCheck) {
      var user = userToCheck || AuthenticationService.getCurrentUser();
      var rols = [];
      
      if (user) {
        rols = user.rols || [];
      }
      return rols.indexOf(rol.trim()) >= 0; 
    },

    principal: function () {
      return Authorization.get({action: 'principal'}).$promise;
    },

    setupCredentials: function (username, requestToken, accessToken, callback) {
      var AuthParams = {
        username: username,
        requestToken: requestToken,
        accessToken: accessToken
      };

      $rootScope.AuthParams = AuthParams;
      localStorage.setItem(Config.authParamsKey, JSON.stringify(AuthParams));
      $http.defaults.headers.common.Authorization = 'Bearer ' + accessToken;
      // cargamos los permisos del usuario
      this.principal().then(function (response) {
        AuthParams.permissions = response.permisos;
        AuthParams.rols = response.roles;
        AuthParams.stamp = response.stamp;
        localStorage.setItem(Config.authParamsKey, JSON.stringify(AuthParams));
        callback(AuthParams);
      });
    },

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
}());

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
