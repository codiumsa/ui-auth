'use strict';

(function () {
  'use strict';

  angular.module('ui.auth.services', []);

  angular.module('ui.auth.directives', ['ui.auth.services']);

  angular.module('ui.auth', ['ngResource', 'ui.auth.services', 'ui.auth.directives']);
})();

(function () {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.Authentication
   * @description
   * # Authentication
   * Service in the ui.auth.
   */

  angular.module('ui.auth.services').factory('AuthenticationService', AuthenticationService);

  AuthenticationService.$inject = ['$resource', 'AuthConfig', '$injector'];

  function AuthenticationService($resource, AuthConfig, $injector) {
    var Authentication = $resource(AuthConfig.serverURL + '/oauth/token');
    var refreshing = false;
    var promise = void 0;

    return {
      login: login,
      refresh: refresh,
      fetchCurrentUser: fetchCurrentUser,
      isLoggedIn: isLoggedIn
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
        return promise;
      }
      refreshing = true;
      var auth = new Authentication({
        grantType: 'refresh_token',
        refreshToken: refreshToken
      });
      var rsp = auth.$save();
      promise = rsp.then(function (data) {
        refreshing = false;
        return data;
      }).then(loginSuccess);
      return promise;
    }

    /**
     * Retorna el usuario actual.
     *
     * @returns {object} Promise que se puede utilizar para recuperar el estado actual.
     */
    function fetchCurrentUser() {
      var resource = $resource(AuthConfig.serverURL + '/oauth/user');
      return resource.get().$promise;
    }

    /**
     * @returns {boolean} Retorna true, si se ha iniciado sesión. False en caso contrario.
     */
    function isLoggedIn() {
      var CurrentUserService = $injector.get('CurrentUserService');
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
})();

(function () {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.Authorization
   * @description
   * # Authorization
   * Service in the ui.auth.
   */

  angular.module('ui.auth.services').factory('AuthorizationService', AuthorizationService);

  AuthorizationService.$inject = ['$resource', 'AuthConfig', '$injector'];

  function AuthorizationService($resource, AuthConfig, $injector) {
    var Authorization = $resource(AuthConfig.serverURL + '/authorization/:action', { action: '@action' });

    return {
      /**
       * Retorna true si el usuario actual de la aplicación posee el permiso dado como
       * parámetro.
       *
       * @param {string} permission - El permiso a corroborar
       * @returns {boolean}
       **/
      hasPermission: function hasPermission(permission) {
        var CurrentUserService = $injector.get('CurrentUserService');
        var permissions = CurrentUserService.getPermissions();
        return permissions.indexOf(permission.trim()) >= 0;
      },

      /**
       * Verifica si el usuario dado como parametro posee los permisos en cuestión.
       *
       * @param {string[]} permissions - lista de permisos a controlar
       * @returns {boolean}
       */
      hasPermissions: function hasPermissions(permissions) {
        var authorized = true;

        for (var i = 0; i < permissions.length; i++) {
          if (!this.hasPermission(permissions[i])) {
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
       * @returns {boolean}
       */
      hasSomePermissions: function hasSomePermissions(permissions) {
        var _this = this;

        return _.some(permissions, function (p) {
          return _this.hasPermission(p);
        });
      },

      /**
       * Verifica si el usuario posee el rol dado como parámetro.
       *
       * @param {string} rol - Rol a controlar
       * @returns {boolean}
       */
      hasRol: function hasRol(rol) {
        var CurrentUserService = $injector.get('CurrentUserService');
        var rols = CurrentUserService.getRols();
        return rols.indexOf(rol.trim()) >= 0;
      },

      /**
       * Helper para determinar si el user actual esta o no autorizado para realizar
       * una acción en particular.
       *
       * @param {boolean} loginRequired - Indica si la acción a realizar requiere que el usuario esté autenticado.
       * @param {string[]} requiredPermissions - Lista de permisos solicitados por la acción.
       * @returns {string} -  loginRequired | notAuthorized | authorized
       */
      authorize: function authorize(loginRequired, requiredPermissions) {
        var CurrentUserService = $injector.get('CurrentUserService');

        if (loginRequired === true && user === undefined) {
          return this.enums.LOGIN_REQUIRED;
        } else if (loginRequired && CurrentUserService.isLoggedIn() && (requiredPermissions === undefined || requiredPermissions.length === 0)) {
          return this.enums.AUTHORIZED;
        } else if (requiredPermissions) {
          var isAuthorized = this.hasPermissions(requiredPermissions);
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
})();

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

  angular.module('ui.auth.services').provider('AuthConfig', function () {

    var options = {};

    this.config = function (opt) {
      angular.extend(options, opt);
    };

    this.$get = [function () {
      return options;
    }];
  });
})();

(function () {
  'use strict';

  /**
   * @ngdoc service
   * @name ui.auth.services.HttpInterceptor
   * @description
   * # HttpInterceptor
   * Factory in the ui.auth.
   */

  angular.module('ui.auth.services').factory('HttpInterceptor', HttpInterceptor);

  HttpInterceptor.$inject = ['$q', '$location', '$injector'];

  function HttpInterceptor($q, $location, $injector) {

    return {
      request: function request(config) {
        var TokenService = $injector.get('TokenService');
        var token = TokenService.getToken();

        if (token) {
          config.headers.Authorization = 'Bearer ' + token;
        }
        config.headers['Content-Type'] = 'application/json';
        return config;
      },

      requestError: function requestError(rejection) {
        var AuthConfig = $injector.get('AuthConfig');

        if (rejection.status === 401) {
          $location.path(AuthConfig.loginPath);
        }
        return $q.reject(rejection);
      },

      response: function response(_response) {
        return _response;
      },

      responseError: function responseError(rejection) {
        var AuthConfig = $injector.get('AuthConfig');
        var $window = $injector.get('$window');
        var $http = $injector.get('$http');

        // verificamos si la renovación del access token falló
        if (rejection.status === 500 && rejection.config.method === 'POST' && rejection.config.url === AuthConfig.serverURL + '/token') {
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
          // {token: ... , refreshToken: ...}
          rsp.then(function (token) {
            TokenService.setToken(token);
            return token;
          });
          rsp.then(deferred.resolve, deferred.reject);
          return deferred.promise.then(function (token) {
            rejection.config.headers.Authorization = 'Bearer ' + token.token;
            return $http(rejection.config);
          });
        }
        return $q.reject(rejection);
      }
    };
  }
})();

(function () {
  'use strict';

  /**
   * Directiva que se encarga de mostrar/ocultar elementos del DOM en base
   * a los permisos que posee el usuario que ha iniciado sesion.
   *
   * atributos disponibles:
   *  - when-login: hide | show, permite ocultar o mostrar el elemento si el usuario inicio sesion.
   *  - permissions: lista de permisos que indican si el elemento se debe mostrar o no.
   *  - requires-login: indica si para mostrar el elemento, el usuario debe iniciar sesion
   *  - some-permissions: lista de permisos. El elmento se muestra o no, si al menos un permiso se encuentra.
   *
   * @ngdoc directive
   * @name ui-auth.directives:auth
   * @description
   * # auth
   */

  angular.module('ui.auth.directives').directive('auth', auth);

  auth.$inject = ['AuthenticationService', 'AuthorizationService'];

  function auth(AuthenticationService, AuthorizationService) {

    return {
      restrict: 'A',
      scope: {
        // expresion que se evalua a un array de strings, o un string donde los valores se separan por comas.
        somePermissions: '=',
        // expresion que se evalua a un array de strings, o un string donde los valores se separan por comas.
        permissions: '='
      },
      link: function link(scope, element, attrs) {
        var requiresLogin = scope.permissions !== undefined || scope.somePermissions !== undefined || attrs.requiresLogin !== undefined;
        var permissions;
        var loggedIn = AuthenticationService.isLoggedIn();
        var remove = requiresLogin && !loggedIn;
        var somePermissions;

        if (attrs.whenLogin) {
          remove = loggedIn ? attrs.whenLogin === 'hide' : attrs.whenLogin === 'show';
        }

        if (scope.permissions) {
          permissions = scope.permissions;

          if (!angular.isArray(permissions)) {
            permissions = scope.permissions.split(',');
          }
        }

        if (permissions) {
          remove = !AuthorizationService.hasPermissions(permissions);
        }

        if (scope.somePermissions) {
          somePermissions = scope.somePermissions;

          if (!angular.isArray(somePermissions)) {
            somePermissions = scope.somePermissions.split(',');
          }
          remove = !AuthorizationService.hasSomePermissions(somePermissions);
        }

        if (remove) {
          element.remove();
        }
      }
    };
  }
})();