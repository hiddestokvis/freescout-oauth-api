<?php

namespace Modules\OAuthApi\Entities;

use Illuminate\Database\Eloquent\Model;

/**
 * Links a webhook of the API & Webhooks module to the authorization that
 * created it.
 */
class OAuthWebhook extends Model
{
    protected $table = 'oauthapi_webhooks';

    // Only created_at, set by hand: Laravel 5.5 cannot drop updated_at alone.
    public $timestamps = false;

    protected $casts = [
        'mailbox_ids' => 'array',
    ];

    protected $dates = [
        'created_at',
    ];

    public function authorization()
    {
        return $this->belongsTo(Authorization::class, 'authorization_id');
    }

    public function user()
    {
        return $this->belongsTo(\App\User::class, 'user_id');
    }

    /**
     * Mailboxes the webhook was asked for, or null for "all mailboxes the
     * user can see".
     */
    public function requestedMailboxIds()
    {
        return is_array($this->mailbox_ids) ? array_map('intval', $this->mailbox_ids) : null;
    }
}
