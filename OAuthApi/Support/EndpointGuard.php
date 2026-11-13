<?php

namespace Modules\OAuthApi\Support;

use App\Conversation;
use App\Customer;
use App\Mailbox;
use App\User;
use Illuminate\Http\Request;

/**
 * Checks one API request against the permissions of the user the access
 * token belongs to, before the API & Webhooks controller runs.
 *
 * Three kinds of work happen here:
 *
 * - Records named in the URL (a conversation, customer, user, mailbox) are
 *   loaded the same way the controller loads them and checked with the
 *   FreeScout policies. A record the user cannot see is answered with
 *   "Not Found", so its existence is not confirmed.
 * - Request fields that name "who is doing this" (byUser, threads[].user,
 *   byUserId) are overwritten with the token's user, so an application
 *   can never act as somebody else.
 * - Request fields that point at other records (a target mailbox, an
 *   assignee, a customer ID) are checked, and the list filters are
 *   narrowed to what the user can see.
 *
 * check() returns null when the request may go ahead, or the response to
 * send instead.
 */
class EndpointGuard
{
    public static function check($method, Request $request, $route, User $user)
    {
        switch ($method) {
            case 'listConversations':
                return self::listConversations($request, $user);

            case 'getConversation':
            case 'listConversationTimelogs':
                return self::conversation($route, $user, 'view');

            case 'listTimelogs':
                return self::listTimelogs($request, $route, $user);

            case 'createTimelog':
                return self::createTimelog($request, $route, $user);

            case 'getMe':
                return null;

            case 'getReport':
                // Reports cover every mailbox; API & Webhooks allows them
                // only to administrators' keys too.
                return $user->isAdmin() ? null : ApiResponse::forbidden('Reports are only available to administrators.');

            case 'updateCustomFields':
            case 'updateTags':
                return self::conversation($route, $user, 'update');

            case 'createConversation':
                return self::createConversation($request, $user);

            case 'updateConversation':
                return self::updateConversation($request, $route, $user);

            case 'deleteConversation':
                return self::deleteConversation($route, $user);

            case 'createThread':
                return self::createThread($request, $route, $user);

            case 'listCustomers':
            case 'createCustomer':
                // Lists are narrowed by ListFilter and the query hooks;
                // FreeScout lets every user create customers.
                return null;

            case 'getCustomer':
            case 'updateCustomer':
            case 'updateCustomerFields':
                return self::customer($route, $user);

            case 'listUsers':
                return null;

            case 'getUser':
                return self::getUser($route, $user);

            case 'createUser':
                return self::createUser($request, $user);

            case 'deleteUser':
                return self::deleteUser($request, $route, $user);

            case 'listMailboxes':
                return self::listMailboxes($request, $user);

            case 'mailboxCustomFields':
            case 'mailboxFolders':
                return self::mailbox($route, $user);

            case 'listTags':
                return self::listTags($request, $user);
        }

        // A scope is mapped for this endpoint but no check is: refuse
        // rather than let it through unchecked.
        \Log::error('[OAuthApi] No access check for API endpoint "'.$method.'"; request refused.');

        return ApiResponse::forbidden('This endpoint is not available to OAuth access tokens.');
    }

    // Conversations.

    protected static function listConversations(Request $request, User $user)
    {
        if ($user->isAdmin()) {
            return null;
        }

        // Narrow the mailbox filter to the user's mailboxes. This keeps
        // page counts right even on API & Webhooks versions without the
        // api.conversations.query hook. "-1" matches nothing; "0" would be
        // ignored by the controller as empty.
        $allowed = Access::mailboxIds($user);
        $requested = self::idList($request->input('mailboxId'));

        $ids = $requested === null ? $allowed : array_values(array_intersect($requested, $allowed));

        self::set($request, 'mailboxId', $ids ? implode(',', $ids) : '-1');

        return null;
    }

    protected static function conversation($route, User $user, $ability)
    {
        $conversation = self::find(Conversation::class, $route->parameter('conversationId'));

        if (!$conversation || !$user->can($ability, $conversation)) {
            return ApiResponse::notFound();
        }

        return null;
    }

    protected static function createConversation(Request $request, User $user)
    {
        $data = $request->all();
        if (self::hasSnakeCollisions($data)) {
            return self::collisionResponse();
        }

        $mailbox = null;
        $mailbox_key = self::snakeKey($data, 'mailbox_id');
        if ($mailbox_key !== null) {
            $mailbox = self::findStrict(Mailbox::class, $data[$mailbox_key]);
            if (!Access::canViewMailbox($user, $mailbox)) {
                return ApiResponse::badRequest('Mailbox not found', 'mailboxId');
            }
            self::set($request, $mailbox_key, $mailbox->id);
        }

        $assign_key = self::snakeKey($data, 'assign_to');
        if ($mailbox && $assign_key !== null) {
            if ($denied = self::checkAssignee($request, $assign_key, $mailbox->id)) {
                return $denied;
            }
        }

        $customer_key = self::snakeKey($data, 'customer');
        if ($customer_key !== null && ($denied = self::checkCustomerReference($data[$customer_key], $user, true))) {
            return $denied;
        }

        $threads_key = self::snakeKey($data, 'threads');
        if ($threads_key !== null && is_array($data[$threads_key])) {
            $threads = $data[$threads_key];
            foreach ($threads as $i => $thread) {
                if (!is_array($thread)) {
                    continue;
                }
                $thread_customer_key = self::snakeKey($thread, 'customer');
                if ($thread_customer_key !== null && ($denied = self::checkCustomerReference($thread[$thread_customer_key], $user, false))) {
                    return $denied;
                }
                // Replies and notes are written by the token's user.
                // Customer threads ignore this field.
                $threads[$i] = self::pin($threads[$i], 'user', $user->id);
            }
            self::set($request, $threads_key, $threads);
        }

        return null;
    }

    protected static function updateConversation(Request $request, $route, User $user)
    {
        $conversation = self::find(Conversation::class, $route->parameter('conversationId'));

        if (!$conversation || !$user->can('update', $conversation)) {
            return ApiResponse::notFound();
        }

        // This controller reads the fields under their exact names, but
        // checking every spelling keeps it safe if that changes.
        $data = $request->all();
        if (self::hasSnakeCollisions($data)) {
            return self::collisionResponse();
        }

        foreach (self::pin($data, 'by_user', $user->id, 'byUser') as $key => $value) {
            if (\Str::snake((string) $key) === 'by_user') {
                self::set($request, $key, $value);
            }
        }

        // Moving to another mailbox: the user needs access to it too.
        $target_mailbox_id = $conversation->mailbox_id;
        $mailbox_key = self::snakeKey($data, 'mailbox_id');
        if ($mailbox_key !== null) {
            $mailbox_id = self::strictId($data[$mailbox_key]);
            if ($mailbox_id === null) {
                return ApiResponse::badRequest('Mailbox not found.', 'mailboxId');
            }
            if ($mailbox_id != $conversation->mailbox_id) {
                $mailbox = Mailbox::find($mailbox_id);
                if (!Access::canViewMailbox($user, $mailbox)) {
                    return ApiResponse::badRequest('Mailbox not found.', 'mailboxId');
                }
                $target_mailbox_id = $mailbox->id;
            }
            self::set($request, $mailbox_key, $mailbox_id);
        }

        $assign_key = self::snakeKey($data, 'assign_to');
        if ($assign_key !== null && ($denied = self::checkAssignee($request, $assign_key, $target_mailbox_id))) {
            return $denied;
        }

        $customer_key = self::snakeKey($data, 'customer_id');
        if ($customer_key !== null && !self::isEmptyReference($data[$customer_key])) {
            $customer = self::findStrict(Customer::class, $data[$customer_key]);
            if (!Access::canViewCustomer($user, $customer)) {
                return ApiResponse::badRequest('Customer not found.', 'customerId');
            }
            self::set($request, $customer_key, $customer->id);
        }

        return null;
    }

    protected static function deleteConversation($route, User $user)
    {
        $conversation = self::find(Conversation::class, $route->parameter('conversationId'));

        if (!Access::canViewConversation($user, $conversation)) {
            return ApiResponse::notFound();
        }
        if (!$user->can('delete', $conversation)) {
            return ApiResponse::forbidden('You do not have permission to delete conversations.');
        }

        return null;
    }

    protected static function createThread(Request $request, $route, User $user)
    {
        $conversation = self::find(Conversation::class, $route->parameter('conversationId'));

        if (!$conversation || !$user->can('update', $conversation)) {
            return ApiResponse::notFound();
        }

        $data = $request->all();
        if (self::hasSnakeCollisions($data)) {
            return self::collisionResponse();
        }

        $customer_key = self::snakeKey($data, 'customer');
        if ($customer_key !== null && ($denied = self::checkCustomerReference($data[$customer_key], $user, false))) {
            return $denied;
        }

        foreach (self::pin($data, 'user', $user->id) as $key => $value) {
            if (\Str::snake((string) $key) === 'user') {
                self::set($request, $key, $value);
            }
        }

        return null;
    }

    // Time logs (Time Tracking module).

    protected static function listTimelogs(Request $request, $route, User $user)
    {
        // Before API & Webhooks 1.0.11x: /conversations/{conversationId}/timelogs.
        if ($route->parameter('conversationId') !== null) {
            return self::conversation($route, $user, 'view');
        }

        // Since then: /timelogs, for every conversation, filtered by
        // ListScopes; optional filters checked here.
        $data = $request->all();

        $conversation_id = $data['conversationId'] ?? null;
        if (!self::isEmptyReference($conversation_id)) {
            if (!Access::canViewConversation($user, self::findStrict(Conversation::class, $conversation_id))) {
                return ApiResponse::notFound();
            }
        }

        return self::checkTimelogUser($request, $data, $user);
    }

    protected static function createTimelog(Request $request, $route, User $user)
    {
        $conversation = self::find(Conversation::class, $route->parameter('conversationId'));
        if (!$conversation || !$user->can('update', $conversation)) {
            return ApiResponse::notFound();
        }

        $data = $request->all();
        if (self::isEmptyReference($data['userId'] ?? null)) {
            // Booked for the token's user.
            self::set($request, 'userId', $user->id);

            return null;
        }

        return self::checkTimelogUser($request, $data, $user);
    }

    /**
     * Time logs of, or for, another user: administrators only (as in
     * API & Webhooks for personal keys).
     */
    protected static function checkTimelogUser(Request $request, array $data, User $user)
    {
        $value = $data['userId'] ?? null;
        if (self::isEmptyReference($value)) {
            return null;
        }

        $user_id = self::strictId($value);
        if ($user_id === null) {
            return ApiResponse::badRequest('User not found.', 'userId');
        }
        if ($user_id != $user->id && !$user->isAdmin()) {
            return ApiResponse::forbidden('Only administrators can use time logs of other users.');
        }
        self::set($request, 'userId', $user_id);

        return null;
    }

    // Tags.

    protected static function listTags(Request $request, User $user)
    {
        // Tags are shared by the whole instance, but the list can be
        // filtered to one conversation's tags.
        $value = $request->all()['conversationId'] ?? null;
        if (self::isEmptyReference($value)) {
            return null;
        }

        $conversation = self::findStrict(Conversation::class, $value);
        if (!Access::canViewConversation($user, $conversation)) {
            return ApiResponse::notFound();
        }

        return null;
    }

    // Customers.

    protected static function customer($route, User $user)
    {
        $customer = self::find(Customer::class, $route->parameter('customerId'));

        if (!Access::canViewCustomer($user, $customer)) {
            return ApiResponse::notFound();
        }

        return null;
    }

    // Users.

    protected static function getUser($route, User $user)
    {
        $target = self::find(User::class, $route->parameter('userId'));

        if (!Access::canViewUser($user, $target)) {
            return ApiResponse::notFound();
        }

        return null;
    }

    protected static function createUser(Request $request, User $user)
    {
        // Administrators only, as API & Webhooks does for personal keys: the
        // controller mass-assigns user fields (permissions, status), which
        // the "manage users" permission does not cover.
        if (!$user->isAdmin()) {
            return ApiResponse::forbidden('Only administrators can create users through the API.');
        }

        return null;
    }

    protected static function deleteUser(Request $request, $route, User $user)
    {
        $target = self::find(User::class, $route->parameter('userId'));

        if (!Access::canViewUser($user, $target)) {
            return ApiResponse::notFound();
        }
        if (!$user->can('delete', $target)) {
            return ApiResponse::forbidden('You do not have permission to delete users.');
        }
        if ($target->id == $user->id) {
            return ApiResponse::forbidden('You cannot delete your own account through the API.');
        }

        self::set($request, 'byUserId', $user->id);

        return null;
    }

    // Mailboxes.

    protected static function listMailboxes(Request $request, User $user)
    {
        // The controller's own "mailboxes of this user" filter. Keeps page
        // counts right; ListFilter removes archived mailboxes.
        if (!$request->has('userId')) {
            self::set($request, 'userId', $user->id);
        }

        return null;
    }

    protected static function mailbox($route, User $user)
    {
        $mailbox = self::find(Mailbox::class, $route->parameter('mailboxId'));

        if (!Access::canViewMailbox($user, $mailbox)) {
            return ApiResponse::notFound();
        }

        return null;
    }

    // Helpers.

    /**
     * An assignee must be able to see the mailbox the conversation is in.
     * The API & Webhooks controller does not check this itself.
     */
    protected static function checkAssignee(Request $request, $key, $mailbox_id)
    {
        $value = $request->all()[$key] ?? null;
        if (self::isEmptyReference($value)) {
            return null;
        }

        $assignee = self::findStrict(User::class, $value);
        if (!$assignee || $assignee->isDeleted() || !$assignee->hasAccessToMailbox($mailbox_id)) {
            return ApiResponse::badRequest('The assignee does not have access to this mailbox.', 'assignTo');
        }
        self::set($request, $key, $assignee->id);

        return null;
    }

    /**
     * A customer object ({"id": 5} or {"email": ...}) given by ID must be
     * a customer the user can see. Lookups by email are allowed, as when
     * writing a new conversation in FreeScout.
     */
    protected static function checkCustomerReference($customer, User $user, $unwrap)
    {
        if (!is_array($customer)) {
            return null;
        }

        // Some clients (Zapier) send [{...}]. createConversation unwraps
        // that when [0] is not empty; createThread never does. Anything
        // that mixes [0] with other fields could be read differently here
        // and in the controller, so it is refused.
        if (array_key_exists(0, $customer) && count($customer) > 1) {
            return ApiResponse::badRequest('Invalid customer object.', 'customer');
        }
        if ($unwrap && !empty($customer[0])) {
            $customer = $customer[0];
            if (!is_array($customer)) {
                return ApiResponse::badRequest('Invalid customer object.', 'customer');
            }
        }

        $id_key = self::snakeKey($customer, 'id');
        if ($id_key === null || self::isEmptyReference($customer[$id_key])) {
            return null;
        }

        $found = self::findStrict(Customer::class, $customer[$id_key]);
        if (!$found) {
            return ApiResponse::badRequest('Customer with the following ID not found.', 'customer');
        }
        if (!Access::canViewCustomer($user, $found)) {
            return ApiResponse::badRequest('Customer with the following ID not found: '.$found->id, 'customer');
        }

        return null;
    }

    /**
     * The API & Webhooks controller renames request fields with
     * Str::snake() before reading most of them: "mailboxId", "MailboxId"
     * and "mailbox_id" all become "mailbox_id", and the last one wins. A
     * request where two fields collapse into one is refused, so the field
     * checked here is always the field the controller uses.
     */
    protected static function hasSnakeCollisions(array $data)
    {
        $seen = [];
        foreach ($data as $key => $value) {
            $snake = \Str::snake((string) $key);
            if (isset($seen[$snake])) {
                return true;
            }
            $seen[$snake] = true;

            if (is_array($value) && self::hasSnakeCollisions($value)) {
                return true;
            }
        }

        return false;
    }

    protected static function collisionResponse()
    {
        return ApiResponse::badRequest('The same field is given more than once, in different spellings.');
    }

    /**
     * The key in $data that the controller will read as $snake, if any.
     */
    protected static function snakeKey(array $data, $snake)
    {
        foreach (array_keys($data) as $key) {
            if (\Str::snake((string) $key) === $snake) {
                return $key;
            }
        }

        return null;
    }

    /**
     * Set a field in $data to $value under whatever spelling it already
     * has, and under $default_key too.
     */
    protected static function pin(array $data, $snake, $value, $default_key = null)
    {
        $existing = self::snakeKey($data, $snake);
        if ($existing !== null) {
            $data[$existing] = $value;
        }
        $data[$default_key ?: $snake] = $value;

        return $data;
    }

    /**
     * Load a record exactly as the controller would (Model::find with the
     * raw value), so this check and the controller always agree on which
     * record is meant.
     */
    protected static function find($class, $id)
    {
        if ($id === null || $id === '' || !is_scalar($id)) {
            return null;
        }

        return $class::find($id);
    }

    /**
     * Load a record named in the request body. Only plain digits are
     * accepted: these checks run before FreeScout's TrimStrings middleware,
     * so "\u00005" would find nothing here and record 5 in the controller.
     */
    protected static function findStrict($class, $value)
    {
        $id = self::strictId($value);

        return $id === null ? null : $class::find($id);
    }

    protected static function strictId($value)
    {
        if (is_int($value) && $value > 0) {
            return $value;
        }
        if (is_string($value) && preg_match('/^[0-9]+$/', $value) && (int) $value > 0) {
            return (int) $value;
        }

        return null;
    }

    protected static function isEmptyReference($value)
    {
        return $value === null || $value === '' || $value === false
            || (is_numeric($value) && (int) $value <= 0);
    }

    /**
     * "1,2,3" or [1, 2, 3] as a list of integers; null when not given.
     */
    protected static function idList($value)
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_array($value)) {
            $value = explode(',', (string) $value);
        }

        return array_values(array_unique(array_map('intval', array_filter($value, 'is_scalar'))));
    }

    /**
     * Set a request field for the controller. The query string is updated
     * too, so a copy there can never win over the value set here.
     */
    protected static function set(Request $request, $key, $value)
    {
        $request->merge([$key => $value]);

        if ($request->query->has($key)) {
            $request->query->set($key, $value);
        }
    }
}
