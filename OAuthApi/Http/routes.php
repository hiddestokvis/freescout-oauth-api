<?php

/**
 * Pages the user's browser visits: need the session.
 */
Route::group(['middleware' => 'web', 'prefix' => \Helper::getSubdirectory(), 'namespace' => 'Modules\OAuthApi\Http\Controllers'], function () {
    // Consent screen.
    Route::get('/oauth/authorize', ['uses' => 'OAuthController@showAuthorize', 'middleware' => ['auth']])->name('oauthapi.authorize');
    Route::post('/oauth/authorize', ['uses' => 'OAuthController@decide', 'middleware' => ['auth']])->name('oauthapi.authorize.decide');

    // Registering applications (Manage » Settings » OAuth Apps).
    Route::post('/oauth-api/clients', ['uses' => 'ClientsController@handle', 'middleware' => ['auth', 'roles'], 'roles' => ['admin']])->name('oauthapi.clients');

    // A user's authorized applications.
    Route::get('/users/authorized-apps/{id}', ['uses' => 'AuthorizedAppsController@index', 'middleware' => ['auth']])->name('oauthapi.user_apps');
    Route::post('/users/authorized-apps/{id}', ['uses' => 'AuthorizedAppsController@revoke', 'middleware' => ['auth']])->name('oauthapi.user_apps.revoke');
});

/**
 * Endpoints applications call directly: no session, no CSRF token.
 */
Route::group(['prefix' => \Helper::getSubdirectory(), 'namespace' => 'Modules\OAuthApi\Http\Controllers'], function () {
    Route::post('/oauth/token', 'OAuthController@token')->name('oauthapi.token');
    Route::post('/oauth/revoke', 'OAuthController@revoke')->name('oauthapi.revoke');
    Route::get('/oauth/userinfo', 'OAuthController@userinfo')->name('oauthapi.userinfo');
    Route::options('/oauth/{endpoint}', 'OAuthController@preflight')->where('endpoint', 'token|revoke|userinfo');

    // Server metadata (RFC 8414). Also under /oauth/ for web servers that
    // refuse paths starting with a dot.
    Route::get('/.well-known/oauth-authorization-server', 'OAuthController@metadata')->name('oauthapi.metadata');
    Route::get('/oauth/metadata', 'OAuthController@metadata');
});
