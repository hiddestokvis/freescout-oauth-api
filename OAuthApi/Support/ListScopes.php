<?php

namespace Modules\OAuthApi\Support;

use App\User;
use Illuminate\Database\Eloquent\Model;

/**
 * Limits the database queries of a list request to what the user can see,
 * with a temporary Eloquent global scope on the listed model.
 *
 * This works on every API & Webhooks version, hooks or not, and makes the
 * page counts exact: without it, a filter such as ?subject= or ?email=
 * would count records the user cannot see, and the totals would reveal
 * them. Only used for the read-only list endpoints, and removed as soon as
 * the controller has answered.
 *
 * Extends Model only to reach the protected static $globalScopes, which
 * Laravel 5.5 offers no public way to remove from.
 */
class ListScopes extends Model
{
    const NAME = 'oauthapi';

    public static $models = [
        'listConversations' => \App\Conversation::class,
        'listCustomers'     => \App\Customer::class,
        'listUsers'         => \App\User::class,
        'listMailboxes'     => \App\Mailbox::class,
        'listTimelogs'      => '\Modules\TimeTracking\Entities\Timelog',
    ];

    public static function apply($method, User $user)
    {
        if (!isset(self::$models[$method]) || !class_exists(self::$models[$method])) {
            return;
        }

        // Work out the allowed IDs now, outside the scope: they come from
        // queries on these same models, which would otherwise run through
        // the scope themselves.
        $constraint = null;

        switch ($method) {
            case 'listConversations':
                if (!$user->isAdmin()) {
                    $mailbox_ids = Access::mailboxIds($user);
                    $only_assigned = $user->canSeeOnlyAssignedConversations();
                    $constraint = function ($query) use ($user, $mailbox_ids, $only_assigned) {
                        Access::scopeConversations($query, $user, $mailbox_ids, $only_assigned);
                    };
                }
                break;

            case 'listCustomers':
                if (Access::customersLimited($user)) {
                    $mailbox_ids = Access::mailboxIds($user);
                    $constraint = function ($query) use ($user, $mailbox_ids) {
                        Access::scopeCustomers($query, $user, $mailbox_ids);
                    };
                }
                break;

            case 'listUsers':
                $user_ids = Access::visibleUserIds($user);
                if ($user_ids !== null) {
                    $constraint = function ($query) use ($user_ids) {
                        $query->whereIn('users.id', $user_ids ?: [0]);
                    };
                }
                break;

            case 'listTimelogs':
                // Time logs of the conversations the user can see.
                if (!$user->isAdmin()) {
                    $mailbox_ids = Access::mailboxIds($user);
                    $only_assigned = $user->canSeeOnlyAssignedConversations();
                    $constraint = function ($query) use ($user, $mailbox_ids, $only_assigned) {
                        $query->whereIn('timelogs.conversation_id', function ($query) use ($user, $mailbox_ids, $only_assigned) {
                            $query->select('conversations.id')->from('conversations');
                            Access::scopeConversations($query, $user, $mailbox_ids, $only_assigned);
                        });
                    };
                }
                break;

            case 'listMailboxes':
                if (!$user->isAdmin()) {
                    $mailbox_ids = Access::mailboxIds($user);
                    $constraint = function ($query) use ($mailbox_ids) {
                        $query->whereIn('mailboxes.id', $mailbox_ids ?: [0]);
                    };
                }
                break;
        }

        if ($constraint) {
            $class = self::$models[$method];
            $class::addGlobalScope(self::NAME, $constraint);
        }
    }

    public static function remove()
    {
        foreach (self::$models as $class) {
            unset(static::$globalScopes[ltrim($class, '\\')][self::NAME]);
        }
    }
}
