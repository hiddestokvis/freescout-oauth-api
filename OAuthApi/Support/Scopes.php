<?php

namespace Modules\OAuthApi\Support;

/**
 * OAuth scopes, and which API endpoint needs which scope.
 *
 * A scope is a ceiling, never a grant: a token with conversations.write can
 * still only change conversations its user is allowed to change. The user's
 * own FreeScout permissions are checked on every request.
 */
class Scopes
{
    const CONVERSATIONS_READ = 'conversations.read';
    const CONVERSATIONS_WRITE = 'conversations.write';
    const CONVERSATIONS_DELETE = 'conversations.delete';
    const CUSTOMERS_READ = 'customers.read';
    const CUSTOMERS_WRITE = 'customers.write';
    const MAILBOXES_READ = 'mailboxes.read';
    const TAGS_READ = 'tags.read';
    const USERS_READ = 'users.read';
    const USERS_WRITE = 'users.write';
    const REPORTS_READ = 'reports.read';
    const WEBHOOKS = 'webhooks';

    /**
     * ApiController method (from the API & Webhooks module) => scope.
     *
     * A method not listed here is refused to OAuth tokens, so an endpoint
     * added by a future API & Webhooks release is never reachable until
     * this module knows how to check it.
     */
    public static $endpoints = [
        // Conversations
        'listConversations'    => self::CONVERSATIONS_READ,
        'getConversation'      => self::CONVERSATIONS_READ,
        'listTimelogs'         => self::CONVERSATIONS_READ,  // per conversation before 1.0.11x, global after
        'listConversationTimelogs' => self::CONVERSATIONS_READ,
        'createConversation'   => self::CONVERSATIONS_WRITE,
        'createTimelog'        => self::CONVERSATIONS_WRITE,
        'updateConversation'   => self::CONVERSATIONS_WRITE,
        'createThread'         => self::CONVERSATIONS_WRITE,
        'updateCustomFields'   => self::CONVERSATIONS_WRITE,
        'updateTags'           => self::CONVERSATIONS_WRITE,
        'deleteConversation'   => self::CONVERSATIONS_DELETE,

        // Customers
        'listCustomers'        => self::CUSTOMERS_READ,
        'getCustomer'          => self::CUSTOMERS_READ,
        'createCustomer'       => self::CUSTOMERS_WRITE,
        'updateCustomer'       => self::CUSTOMERS_WRITE,
        'updateCustomerFields' => self::CUSTOMERS_WRITE,

        // Users
        'listUsers'            => self::USERS_READ,
        'getUser'              => self::USERS_READ,
        'createUser'           => self::USERS_WRITE,
        'deleteUser'           => self::USERS_WRITE,

        // Mailboxes
        'listMailboxes'        => self::MAILBOXES_READ,
        'mailboxCustomFields'  => self::MAILBOXES_READ,
        'mailboxFolders'       => self::MAILBOXES_READ,

        // Tags
        'listTags'             => self::TAGS_READ,

        // Reports
        'getReport'            => self::REPORTS_READ,

        // Webhooks
        'listWebhooks'         => self::WEBHOOKS,
        'createWebhook'        => self::WEBHOOKS,
        'deleteWebhook'        => self::WEBHOOKS,
    ];

    // Endpoints any valid token may call, whatever its scopes.
    public static $unscoped = [
        'getMe',
    ];

    // Scopes most applications should not need. Highlighted in the UI.
    public static $sensitive = [
        self::CONVERSATIONS_DELETE,
        self::USERS_WRITE,
        self::WEBHOOKS,
    ];

    public static function all()
    {
        return array_values(array_unique(array_values(self::$endpoints)));
    }

    public static function forEndpoint($method)
    {
        return self::$endpoints[$method] ?? null;
    }

    public static function isUnscoped($method)
    {
        return in_array($method, self::$unscoped, true);
    }

    /**
     * Keep only real scope names, in a stable order.
     */
    public static function valid($scopes)
    {
        if (!is_array($scopes)) {
            return [];
        }

        return array_values(array_intersect(self::all(), $scopes));
    }

    /**
     * Parse a space-separated scope string (RFC 6749 section 3.3).
     * Returns null when it contains a scope that does not exist.
     */
    public static function parse($value)
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (!is_string($value)) {
            return null;
        }

        $scopes = array_values(array_unique(array_filter(preg_split('/\s+/', trim($value)), 'strlen')));

        if (count(self::valid($scopes)) != count($scopes)) {
            return null;
        }

        return self::valid($scopes);
    }

    public static function toString($scopes)
    {
        return implode(' ', self::valid($scopes));
    }

    /**
     * Scopes grouped for display, with plain descriptions.
     */
    public static function catalogue()
    {
        return [
            __('Conversations') => [
                self::CONVERSATIONS_READ   => __('Read conversations, threads and time logs'),
                self::CONVERSATIONS_WRITE  => __('Create and update conversations, reply, add notes, tags, custom fields and time logs'),
                self::CONVERSATIONS_DELETE => __('Delete conversations forever'),
            ],
            __('Customers') => [
                self::CUSTOMERS_READ  => __('Read customers'),
                self::CUSTOMERS_WRITE => __('Create and update customers'),
            ],
            __('Mailboxes') => [
                self::MAILBOXES_READ => __('Read mailboxes, their folders and custom fields'),
            ],
            __('Tags') => [
                self::TAGS_READ => __('Read tags'),
            ],
            __('Reports') => [
                self::REPORTS_READ => __('Read reports (administrators only)'),
            ],
            __('Users') => [
                self::USERS_READ  => __('Read users'),
                self::USERS_WRITE => __('Create and delete users (administrators only)'),
            ],
            __('Webhooks') => [
                self::WEBHOOKS => __('Receive webhooks about conversations and customers'),
            ],
        ];
    }

    public static function description($scope)
    {
        foreach (self::catalogue() as $group) {
            if (isset($group[$scope])) {
                return $group[$scope];
            }
        }

        return $scope;
    }
}
