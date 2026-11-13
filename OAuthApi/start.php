<?php

/*
|--------------------------------------------------------------------------
| Register Namespaces And Routes
|--------------------------------------------------------------------------
|
| The OAuth endpoints (authorize, token, revoke) and the module's own pages
| live here. The API itself stays in the API & Webhooks module.
|
*/

if (!app()->routesAreCached()) {
    require __DIR__.'/Http/routes.php';
}
