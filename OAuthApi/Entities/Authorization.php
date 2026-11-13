<?php

namespace Modules\OAuthApi\Entities;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\WebhookManager;

/**
 * A user's consent for one application.
 */
class Authorization extends Model
{
    protected $table = 'oauthapi_authorizations';

    protected $casts = [
        'scopes' => 'array',
    ];

    protected $dates = [
        'revoked_at',
        'last_used_at',
    ];

    protected $fillable = ['client_id', 'user_id'];

    public function client()
    {
        return $this->belongsTo(Client::class, 'client_id');
    }

    public function user()
    {
        return $this->belongsTo(\App\User::class, 'user_id');
    }

    public function tokens()
    {
        return $this->hasMany(Token::class, 'authorization_id');
    }

    public function isRevoked()
    {
        return !empty($this->revoked_at);
    }

    /**
     * Whether tokens of this authorization may be used right now: not
     * revoked, the application is enabled, and the user can still log in.
     */
    public function isUsable()
    {
        if ($this->isRevoked()) {
            return false;
        }

        $client = $this->client;
        if (!$client || !$client->active) {
            return false;
        }

        $user = $this->user;

        return $user && $user->isActive();
    }

    /**
     * The scopes the user agreed to, limited to what the application is
     * currently allowed. An administrator taking a scope away from an
     * application takes effect at once.
     */
    public function effectiveScopes()
    {
        $client = $this->client;
        if (!$client) {
            return [];
        }

        return array_values(array_intersect(Scopes::valid($this->scopes), $client->allowedScopes()));
    }

    public function covers(array $scopes)
    {
        return !$this->isRevoked() && !array_diff($scopes, Scopes::valid($this->scopes));
    }

    /**
     * Revoke the authorization: every token stops working and the
     * application's webhooks are deleted.
     */
    public function revoke()
    {
        $now = Carbon::now();

        if (!$this->revoked_at) {
            $this->revoked_at = $now;
            $this->save();
        }

        Token::where('authorization_id', $this->id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $now]);

        WebhookManager::deleteForAuthorization($this);
    }

    /**
     * Last used time and IP. Written at most once a minute per
     * authorization: accurate enough to spot unused applications.
     */
    public function recordUsage($ip)
    {
        if (!\Cache::add('oauthapi_used_'.$this->id, 1, 1)) {
            return;
        }

        self::where('id', $this->id)->update([
            'last_used_at' => Carbon::now(),
            'last_used_ip' => mb_substr((string) $ip, 0, 45),
        ]);
    }
}
