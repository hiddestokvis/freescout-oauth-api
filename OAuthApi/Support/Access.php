<?php

namespace Modules\OAuthApi\Support;

use App\Conversation;
use App\User;

/**
 * What a FreeScout user can see, in the same terms FreeScout itself uses:
 * the core policies (ConversationPolicy, CustomerPolicy, UserPolicy) for
 * single records, and matching query constraints for lists.
 *
 * - Admins see everything.
 * - Other users see the conversations of the mailboxes they have access
 *   to (archived mailboxes excluded), and only the conversations assigned
 *   to them or created by them when they have the "see only assigned
 *   conversations" restriction.
 * - Customers are visible to all users unless "limit user customer
 *   visibility" is on; then only customers with a conversation in one of
 *   the user's mailboxes.
 * - Other users are visible when they share a mailbox with the user.
 */
class Access
{
    /**
     * The FreeScout user an API request acts as, or null when the request
     * did not use an OAuth access token.
     */
    public static function userFor($request)
    {
        return $request ? $request->attributes->get('oauthapi_user') : null;
    }

    /**
     * API & Webhooks 1.0.11x added a user permission, "Users are allowed to
     * access API" (api.access): users without it, other than admins, may
     * not use the API at all. OAuth follows the same rule. Older versions
     * have no such permission.
     */
    public static function apiAllowed(User $user)
    {
        $class = '\Modules\ApiWebhooks\Entities\ApiKey';
        if (class_exists($class) && method_exists($class, 'isApiAccessible')) {
            return (bool) $class::isApiAccessible($user);
        }

        return true;
    }

    public static function mailboxIds(User $user)
    {
        return array_map('intval', $user->mailboxesIdsCanView());
    }

    // Conversations.

    public static function canViewConversation(User $user, $conversation)
    {
        return $conversation && $user->can('view', $conversation);
    }

    public static function scopeConversations($query, User $user, $mailbox_ids = null, $only_assigned = null)
    {
        if ($user->isAdmin()) {
            return $query;
        }

        $mailbox_ids = $mailbox_ids === null ? self::mailboxIds($user) : $mailbox_ids;
        $only_assigned = $only_assigned === null ? $user->canSeeOnlyAssignedConversations() : $only_assigned;

        $query->whereIn('conversations.mailbox_id', $mailbox_ids ?: [0]);

        if ($only_assigned) {
            $query->where(function ($query) use ($user) {
                $query->where('conversations.user_id', $user->id)
                    ->orWhere('conversations.created_by_user_id', $user->id);
            });
        }

        return $query;
    }

    // Customers.

    public static function customersLimited(User $user)
    {
        return config('app.limit_user_customer_visibility') && !$user->isAdmin();
    }

    public static function canViewCustomer(User $user, $customer)
    {
        return $customer && $user->can('view', $customer);
    }

    public static function scopeCustomers($query, User $user, $mailbox_ids = null)
    {
        if (!self::customersLimited($user)) {
            return $query;
        }

        $mailbox_ids = ($mailbox_ids === null ? self::mailboxIds($user) : $mailbox_ids) ?: [0];

        $query->whereExists(function ($query) use ($mailbox_ids) {
            $query->select(\DB::raw(1))
                ->from('conversations')
                ->whereColumn('conversations.customer_id', 'customers.id')
                ->whereIn('conversations.mailbox_id', $mailbox_ids);
        });

        return $query;
    }

    // Users.

    /**
     * IDs of the users this user can see, or null for everyone.
     */
    public static function visibleUserIds(User $user)
    {
        if ($user->isAdmin()) {
            return null;
        }

        $ids = $user->whichUsersCanView(null, false)->pluck('id')->all();
        $ids[] = $user->id;

        return array_values(array_unique(array_map('intval', $ids)));
    }

    public static function canViewUser(User $user, $target)
    {
        if (!$target) {
            return false;
        }

        $ids = self::visibleUserIds($user);

        return $ids === null || in_array((int) $target->id, $ids, true);
    }

    public static function scopeUsers($query, User $user)
    {
        $ids = self::visibleUserIds($user);
        if ($ids !== null) {
            $query->whereIn('users.id', $ids);
        }

        return $query;
    }

    // Mailboxes.

    public static function canViewMailbox(User $user, $mailbox)
    {
        return $mailbox && $user->hasAccessToMailbox($mailbox->id);
    }

    public static function scopeMailboxes($query, User $user)
    {
        if (!$user->isAdmin()) {
            $query->whereIn('mailboxes.id', self::mailboxIds($user) ?: [0]);
        }

        return $query;
    }

    /**
     * Of the given conversation IDs, those the user can see. One query,
     * same rules as ConversationPolicy::view().
     */
    public static function visibleConversationIds(User $user, array $ids)
    {
        if (!$ids) {
            return [];
        }

        $query = Conversation::whereIn('conversations.id', $ids);
        self::scopeConversations($query, $user);

        return array_map('intval', $query->pluck('conversations.id')->all());
    }

    /**
     * Of the given customer IDs, those the user can see.
     */
    public static function visibleCustomerIds(User $user, array $ids)
    {
        if (!self::customersLimited($user)) {
            return $ids;
        }
        if (!$ids) {
            return [];
        }

        return array_map('intval', Conversation::whereIn('customer_id', $ids)
            ->whereIn('mailbox_id', self::mailboxIds($user) ?: [0])
            ->distinct()
            ->pluck('customer_id')
            ->all());
    }
}
