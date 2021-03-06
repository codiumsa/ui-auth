# ui-auth

Librería que ofrece helpers para autenticación y autorización vía 
[securium-oauth](https://gitlab.com/codium/securium-oauth)

[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)

### configuracion

ui-auth espera que los parametros de configuracion se hagan a través de AuthConfigProvider. Ejemplo:

```javascript
angular
  .module('myApp', [])
  .config(config);

config.$inject['AuthConfigProvider'];

function config(AuthConfigProvider) {
  AuthConfigProvider.config({
    serverURL: 'https://localhost/api',
    loginPath: '/login'
  });
}
```

### TokenService

ui-auth necesita saber cómo obtener el token/refreshToken de la sesión actual, para eso se debe definir el siguiente servicio.

```javascript
angular
  .module('myApp')
  .factory('TokenService', TokenService);
    
  function TokenService() {
    return {
      getToken: function() {
        return '123456789';
      },

      getRefreshToken: function() {
        return 'adsfasdf';
      },

      /**
       * Método llamado cada vez que se actualiza el par access_token/refresh_token.
       * @param {object} token
       */
      setToken(token) {
        // actualizar token
      }
    }
  }    
```



### CurrentUserService

ui-auth necesita saber cómo obtener los roles/permisos de la sesión actual, para eso se debe definir el siguiente servicio.

```javascript
angular
  .module('myApp')
  .factory('CurrentUserService', CurrentUserService);
    
  function CurrentUserService() {
    return {
      getRols: function() {
        return ['admin'];
      },

      getPermissions: function() {
        return ['create_users'];
      },

      isLoggedIn: function() {
        return true;
      }
    }
  }    
```