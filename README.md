# ui-auth

Librería que ofrece helpers para autenticación y autorización vía 
[securium-oauth](https://gitlab.com/codium/securium-oauth)


## configuracion

ui-auth espera que los parametros de configuracion se hagan a través de AuthConfigProvider. Ejemplo:

```
  angular
    .module('myApp', [])
    .config(config);
  
  config.$inject['AuthConfigProvider'];

  function config(AuthConfigProvider) {
    AuthConfigProvider.config({
      serverURL: 'https://localhost/api'
    });
  }
```
