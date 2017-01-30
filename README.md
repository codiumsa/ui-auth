# ui-auth

Librería que ofrece helpers para autenticación y autorización vía 
[securium-oauth](https://gitlab.com/codium/securium-oauth)


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
      }
    }
  }    
```
