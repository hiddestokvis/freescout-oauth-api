<?php

return [
    'name' => 'OAuthApi',

    // Emergency switch. Set OAUTHAPI_DISABLED=true in the FreeScout .env
    // file to turn the module off without uninstalling it. OAuth access
    // tokens stop working at once; the master API key is not affected.
    'disabled' => env('OAUTHAPI_DISABLED', false),
];
