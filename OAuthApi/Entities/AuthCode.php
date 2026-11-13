<?php

namespace Modules\OAuthApi\Entities;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Modules\OAuthApi\Support\Secrets;
use Modules\OAuthApi\Support\Settings;

/**
 * A single-use authorization code.
 */
class AuthCode extends Model
{
    protected $table = 'oauthapi_codes';

    public $timestamps = false;

    protected $casts = [
        'scopes' => 'array',
    ];

    protected $dates = [
        'expires_at',
        'used_at',
        'created_at',
    ];

    public function authorization()
    {
        return $this->belongsTo(Authorization::class, 'authorization_id');
    }

    /**
     * Create a code and return its plain value.
     */
    public static function issue(Authorization $authorization, array $scopes, $redirect_uri, $code_challenge, $code_challenge_method)
    {
        $plain = Secrets::generate();

        $code = new self();
        $code->authorization_id = $authorization->id;
        $code->code_hash = Secrets::hash($plain);
        $code->scopes = array_values($scopes);
        $code->redirect_uri = $redirect_uri;
        $code->code_challenge = $code_challenge;
        $code->code_challenge_method = $code_challenge ? $code_challenge_method : null;
        $code->created_at = Carbon::now();
        $code->expires_at = Carbon::now()->addMinutes(Settings::CODE_TTL_MINUTES);
        $code->save();

        return $plain;
    }

    public static function findByPlain($plain)
    {
        if (!is_string($plain) || $plain === '') {
            return null;
        }

        return self::where('code_hash', Secrets::hash($plain))->first();
    }

    public function isExpired()
    {
        return !$this->expires_at || $this->expires_at->isPast();
    }

    /**
     * Mark the code used. Returns false when another request got there
     * first, so a code can never be exchanged twice.
     */
    public function markUsed()
    {
        $updated = self::where('id', $this->id)
            ->whereNull('used_at')
            ->update(['used_at' => Carbon::now()]);

        return $updated == 1;
    }

    /**
     * PKCE check (RFC 7636). Only S256 is supported.
     */
    public function verifierMatches($verifier)
    {
        if (!$this->code_challenge) {
            return true;
        }
        if (!is_string($verifier) || !preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier)) {
            return false;
        }

        $computed = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return hash_equals($this->code_challenge, $computed);
    }
}
