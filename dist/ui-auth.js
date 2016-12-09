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

(function () {
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
      login: login
    };

    /**
     * Autenticacion basada en username/password
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
     * Login success callback para registrar en el localStorage los
     * datos de autenticación.
     *
     * @param {object} data - datos de autenticacion
     */
    function loginSuccess(data) {
      localStorage.setItem(AuthConfig.preffix, JSON.stringify(data));
    }

    /**
     * retorna la informacion de autenticacion.
     *
     * @returns {object}
     */
    function getCurrent() {
      var user = localStorage.getItem(AuthConfig.preffix);

      if (user) {
        user = JSON.parse(user);
      }
      return user;
    }

    /**
     * helper para determinar si el user actual se encuentra autenticado.
     */
    function isLoggedIn() {
      var authenticate = this.getCurrent();
      return !!authenticate;
    }
  }
} ());

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
       *
       * @param {string} permission - El permiso a corroborar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       **/
      hasPermission: function (permission, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrent();
        var permissions = [];

        if (user) {
          permissions = user.permissions || [];
        }
        return permissions.indexOf(permission.trim()) >= 0;
      },

      /**
       * Verifica si el usuario dado como parametro posee los permisos en cuestion.
       *
       * @param {string[]} permissions - lista de permisos a controlar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
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

      /**
       * Helper para determinar si el usuario posee al menos un permiso.
       *
       * @param {string[]} permissions - lista de permisos
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
      hasAnyPermissions: function (permissions, userToCheck) {
        var self = this;
        return _.some(permissions, function (p) {
          return self.hasPermission(p, userToCheck);
        });
      },

      /**
       * Verifica si el usuario posee el rol dado como parámetro.
       *
       * @param {string} rol - Rol a controlar
       * @param {Object} userToCheck - Parametro opcional que indica el usuario sobre el cual se desea hacer la verificación
       * @returns {boolean}
       */
      hasRol: function (rol, userToCheck) {
        var user = userToCheck || AuthenticationService.getCurrent();
        var rols = [];

        if (user) {
          rols = user.rols || [];
        }
        return rols.indexOf(rol.trim()) >= 0;
      },

      /**
       * Metodo que se encarga de recuperar del servidor los permisos que posee el usuario
       * actual.
       *
       * @returns {Promise}
       */
      principal: function () {
        return Authorization.get({ action: 'principal' }).$promise;
      },

      /**
       * Helper para determinar si el user actual esta o no autorizado para realizar
       * un acción en particular.
       *
       * @param {boolean} loginRequired - Indica si la acción a realizar requiere que el usuario esté autenticado.
       * @param {string[]} requiredPermissions - Lista de permisos solicitados por la acción.
       * @returns {string} -  loginRequired | notAuthorized | authorized
       */
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

(function () {
  'use strict';

  /**
   * Provider para configuracion ui.auth.
   *
   * @ngdoc service
   * @name ui.auth.AuthConfig
   * @description
   * # AuthConfig
   */
  angular.module('ui.auth')
    .provider('AuthConfig', function () {

      var options = {};

      this.config = function (opt) {
        angular.extend(options, opt);
      };

      this.$get = [function () {
        return options;
      }];
    });
} ());

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
