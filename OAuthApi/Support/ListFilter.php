<?php

namespace Modules\OAuthApi\Support;

use App\User;
use Illuminate\Http\JsonResponse;

/**
 * Last line of defence for list endpoints: removes every item the user
 * cannot see from the response, after the controller ran.
 *
 * Normally nothing is removed: EndpointGuard narrows the request and the
 * api.*.query hooks narrow the database query. Those hooks only exist in
 * recent API & Webhooks versions, though, and this filter keeps OAuth
 * tokens safe on older ones too. When it does remove items, page counts
 * in the response are no longer exact, and a warning is logged once a day
 * suggesting an API & Webhooks update.
 */
class ListFilter
{
    public static $lists = [
        'listConversations' => 'conversations',
        'listCustomers'     => 'customers',
        'listUsers'         => 'users',
        'listMailboxes'     => 'mailboxes',
        'listTimelogs'      => 'timelogs',
    ];

    public static function apply($method, $response, User $user)
    {
        if (!isset(self::$lists[$method]) || $response->getStatusCode() != 200) {
            return $response;
        }

        $key = self::$lists[$method];
        $data = json_decode($response->getContent(), true);

        if (!is_array($data) || !isset($data['_embedded'][$key]) || !is_array($data['_embedded'][$key])) {
            return $response;
        }

        $items = $data['_embedded'][$key];

        // Time logs are checked by their conversation. Per-conversation
        // lists (older versions) have no conversationId and were checked
        // before the controller ran.
        $id_field = $key == 'timelogs' ? 'conversationId' : 'id';
        if ($key == 'timelogs' && $items && !array_key_exists('conversationId', $items[0])) {
            return $response;
        }

        $ids = [];
        foreach ($items as $item) {
            if (isset($item[$id_field])) {
                $ids[] = (int) $item[$id_field];
            }
        }

        $allowed = array_flip(self::visibleIds($key, $ids, $user));

        $kept = array_values(array_filter($items, function ($item) use ($allowed, $id_field) {
            return isset($item[$id_field]) && isset($allowed[(int) $item[$id_field]]);
        }));

        if (count($kept) == count($items)) {
            return $response;
        }

        $data['_embedded'][$key] = $kept;

        if ($response instanceof JsonResponse) {
            $response->setData($data);
        } else {
            $response->setContent(json_encode($data));
        }

        if (\Cache::add('oauthapi_list_filtered_'.$key, 1, 60 * 24)) {
            \Log::error('[OAuthApi] Removed '.$key.' the user cannot see from an API list response. '
                .'Update the API & Webhooks module so lists are filtered in the database and page counts stay exact.');
        }

        return $response;
    }

    protected static function visibleIds($key, array $ids, User $user)
    {
        switch ($key) {
            case 'conversations':
            case 'timelogs':
                return Access::visibleConversationIds($user, $ids);

            case 'customers':
                return Access::visibleCustomerIds($user, $ids);

            case 'users':
                $visible = Access::visibleUserIds($user);

                return $visible === null ? $ids : array_values(array_intersect($ids, $visible));

            case 'mailboxes':
                return $user->isAdmin() ? $ids : array_values(array_intersect($ids, Access::mailboxIds($user)));
        }

        return [];
    }
}
