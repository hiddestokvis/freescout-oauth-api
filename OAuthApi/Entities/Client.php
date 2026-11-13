<?php

namespace Modules\OAuthApi\Entities;

use Illuminate\Database\Eloquent\Model;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\Secrets;

/**
 * An application registered by an administrator.
 */
class Client extends Model
{
    protected $table = 'oauthapi_clients';

    protected $casts = [
        'redirect_uris' => 'array',
        'scopes'        => 'array',
        'confidential'  => 'boolean',
        'active'        => 'boolean',
    ];

    // Hosts for which RFC 8252 loopback redirects are allowed: plain http,
    // and any port (native apps pick a free port at run time).
    public static $loopback_hosts = ['127.0.0.1', '[::1]', 'localhost'];

    public function authorizations()
    {
        return $this->hasMany(Authorization::class, 'client_id');
    }

    public static function findByClientId($client_id)
    {
        if (!is_string($client_id) || $client_id === '') {
            return null;
        }

        return self::where('client_id', $client_id)->first();
    }

    public static function generateClientId()
    {
        return Secrets::generate(Secrets::CLIENT_ID_PREFIX, 12);
    }

    /**
     * Set a new secret and return it. Only its hash is kept.
     */
    public function regenerateSecret()
    {
        $plain = Secrets::generate(Secrets::CLIENT_SECRET_PREFIX);
        $this->secret_hash = Secrets::hash($plain);

        return $plain;
    }

    public function checkSecret($plain)
    {
        if (!$this->confidential || !$this->secret_hash || !is_string($plain) || $plain === '') {
            return false;
        }

        return hash_equals($this->secret_hash, Secrets::hash($plain));
    }

    /**
     * Scopes this application may ask for.
     */
    public function allowedScopes()
    {
        return Scopes::valid($this->scopes);
    }

    public function redirectUris()
    {
        return is_array($this->redirect_uris) ? array_values($this->redirect_uris) : [];
    }

    /**
     * Exact match against the registered redirect URIs. Loopback URIs
     * match on any port (RFC 8252 section 7.3).
     */
    public function hasRedirectUri($uri)
    {
        if (!is_string($uri) || $uri === '') {
            return false;
        }

        foreach ($this->redirectUris() as $registered) {
            if (hash_equals($registered, $uri)) {
                return true;
            }
            if (self::isLoopback($registered) && self::withoutPort($registered) === self::withoutPort($uri)) {
                return true;
            }
        }

        return false;
    }

    public static function isLoopback($uri)
    {
        $parts = parse_url($uri);

        return !empty($parts['scheme']) && strtolower($parts['scheme']) == 'http'
            && !empty($parts['host']) && in_array(strtolower($parts['host']), self::$loopback_hosts);
    }

    protected static function withoutPort($uri)
    {
        $parts = parse_url($uri);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }

        return strtolower($parts['scheme']).'://'.strtolower($parts['host'])
            .($parts['path'] ?? '')
            .(isset($parts['query']) ? '?'.$parts['query'] : '');
    }

    /**
     * Check a redirect URI typed by an administrator.
     * Returns an error message, or null when it is fine.
     */
    public static function redirectUriError($uri)
    {
        if (strlen($uri) > 2000) {
            return __('Redirect URI is too long: :uri', ['uri' => $uri]);
        }

        $parts = parse_url($uri);
        if (!$parts || empty($parts['scheme'])) {
            return __('Redirect URI must be an absolute URI: :uri', ['uri' => $uri]);
        }
        if (isset($parts['fragment']) || strpos($uri, '#') !== false) {
            return __('Redirect URI must not contain a fragment (#): :uri', ['uri' => $uri]);
        }
        if (preg_match('/\s/', $uri)) {
            return __('Redirect URI must not contain spaces: :uri', ['uri' => $uri]);
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme == 'https') {
            return empty($parts['host']) ? __('Redirect URI has no host: :uri', ['uri' => $uri]) : null;
        }
        if ($scheme == 'http') {
            return self::isLoopback($uri)
                ? null
                : __('Plain http is only allowed for 127.0.0.1, [::1] and localhost: :uri', ['uri' => $uri]);
        }
        // Private-use schemes for native apps, e.g. com.example.app:/callback.
        if (in_array($scheme, ['javascript', 'data', 'vbscript', 'file', 'about', 'blob', 'ftp', 'ws', 'wss'])) {
            return __('This kind of redirect URI is not allowed: :uri', ['uri' => $uri]);
        }

        return null;
    }

    /**
     * Revoke every user's authorization of this application.
     */
    public function revokeAll()
    {
        foreach ($this->authorizations()->whereNull('revoked_at')->get() as $authorization) {
            $authorization->revoke();
        }
    }

    public function activeAuthorizationsCount()
    {
        return $this->authorizations()->whereNull('revoked_at')->count();
    }
}
