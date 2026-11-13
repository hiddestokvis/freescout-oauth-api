<?php

namespace Modules\OAuthApi\Support;

use Illuminate\Http\Request;
use Modules\OAuthApi\Entities\Client;

/**
 * The parameters of an authorization request (RFC 6749 section 4.1.1,
 * with PKCE from RFC 7636), validated.
 *
 * Problems with the client or the redirect URI are shown to the user and
 * never redirected (the redirect URI cannot be trusted yet). Anything else
 * is sent back to the application as an OAuth error.
 */
class AuthorizeRequest
{
    public $client;
    public $redirect_uri;
    public $redirect_uri_given = false;
    public $scopes = [];
    public $state;
    public $code_challenge;
    public $code_challenge_method;
    public $prompt;

    // Set when the request is invalid.
    public $page_error;       // shown to the user
    public $redirect_error;   // [error, description] sent to the application

    public static function fromRequest(Request $request)
    {
        $params = new self();

        // Client.
        $client = Client::findByClientId($request->input('client_id'));
        if (!$client || !$client->active) {
            $params->page_error = __('This application is not known, or it has been disabled. Please contact your FreeScout administrator.');

            return $params;
        }
        $params->client = $client;

        // Redirect URI.
        $redirect_uri = $request->input('redirect_uri');
        if ($redirect_uri === null || $redirect_uri === '') {
            $registered = $client->redirectUris();
            if (count($registered) != 1) {
                $params->page_error = __('The application did not say where to return to (redirect_uri is missing).');

                return $params;
            }
            $params->redirect_uri = $registered[0];
        } elseif (!$client->hasRedirectUri($redirect_uri)) {
            $params->page_error = __('The application asked to return to an address that is not registered for it (redirect_uri mismatch).');

            return $params;
        } else {
            $params->redirect_uri = $redirect_uri;
            $params->redirect_uri_given = true;
        }

        // From here on errors go back to the application.
        $state = $request->input('state');
        $params->state = is_scalar($state) ? (string) $state : null;

        if ($request->input('response_type') !== 'code') {
            $params->redirect_error = ['unsupported_response_type', 'Only response_type=code is supported.'];

            return $params;
        }

        $scopes = Scopes::parse($request->input('scope'));
        if ($scopes === null) {
            $params->redirect_error = ['invalid_scope', 'Unknown scope. Supported: '.implode(' ', Scopes::all())];

            return $params;
        }
        if (!$scopes) {
            $scopes = $client->allowedScopes();
        }
        if (!$scopes || array_diff($scopes, $client->allowedScopes())) {
            $params->redirect_error = ['invalid_scope', 'The application is not allowed to request this scope.'];

            return $params;
        }
        $params->scopes = $scopes;

        // PKCE. Required for public clients, optional for confidential
        // ones; only S256.
        $challenge = $request->input('code_challenge');
        $method = $request->input('code_challenge_method');
        if ($challenge !== null && $challenge !== '') {
            if ($method !== 'S256') {
                $params->redirect_error = ['invalid_request', 'code_challenge_method must be S256.'];

                return $params;
            }
            if (!is_string($challenge) || !preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge)) {
                $params->redirect_error = ['invalid_request', 'code_challenge is not a valid S256 challenge.'];

                return $params;
            }
            $params->code_challenge = $challenge;
            $params->code_challenge_method = 'S256';
        } elseif (!$client->confidential) {
            $params->redirect_error = ['invalid_request', 'PKCE is required: send code_challenge and code_challenge_method=S256.'];

            return $params;
        }

        $prompt = $request->input('prompt');
        $params->prompt = in_array($prompt, ['none', 'consent'], true) ? $prompt : null;

        return $params;
    }

    public function isValid()
    {
        return !$this->page_error && !$this->redirect_error;
    }

    /**
     * Where to send the user back to, with the given query parameters.
     */
    public function redirectUrl(array $params)
    {
        if ($this->state !== null) {
            $params['state'] = $this->state;
        }
        // RFC 9207: lets the application check which server answered.
        $params['iss'] = Settings::issuer();

        $separator = strpos($this->redirect_uri, '?') === false ? '?' : '&';

        return $this->redirect_uri.$separator.http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    public function errorRedirectUrl($error = null, $description = null)
    {
        if ($error === null) {
            list($error, $description) = $this->redirect_error;
        }

        return $this->redirectUrl(['error' => $error, 'error_description' => $description]);
    }

    /**
     * The fields to carry through the consent form.
     */
    public function formFields()
    {
        return array_filter([
            'client_id'             => $this->client->client_id,
            'redirect_uri'          => $this->redirect_uri_given ? $this->redirect_uri : null,
            'response_type'         => 'code',
            'scope'                 => Scopes::toString($this->scopes),
            'state'                 => $this->state,
            'code_challenge'        => $this->code_challenge,
            'code_challenge_method' => $this->code_challenge_method,
        ], function ($value) {
            return $value !== null;
        });
    }
}
