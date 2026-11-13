<?php

namespace Modules\OAuthApi\Support;

use App\Conversation;
use App\Customer;
use App\User;
use Illuminate\Http\Request;
use Modules\OAuthApi\Entities\Authorization;
use Modules\OAuthApi\Entities\OAuthWebhook;
use Modules\OAuthApi\Exceptions\WebhookSuppressed;

/**
 * Webhooks for OAuth applications.
 *
 * In the API & Webhooks module every webhook is instance-wide: it receives
 * every event of every mailbox. For OAuth tokens this module answers the
 * webhook endpoints itself:
 *
 * - An application only lists and deletes the webhooks it created.
 * - A webhook it creates is a normal API & Webhooks webhook (same signing,
 *   delivery, retries and logs), linked here to the authorization.
 * - Just before each delivery, guardDelivery() checks the event against
 *   the user's access at that moment, and stops it when the user can no
 *   longer see the conversation or customer.
 */
class WebhookManager
{
    // Per authorization, to keep a runaway application in check.
    const MAX_PER_AUTHORIZATION = 25;

    public static $methods = ['listWebhooks', 'createWebhook', 'deleteWebhook'];

    public static function handles($method)
    {
        return in_array($method, self::$methods);
    }

    public static function available()
    {
        return class_exists('\Webhook') && class_exists('\ApiWebhooks');
    }

    /**
     * For API & Webhooks versions that lack one of the webhook routes
     * (older ones have no GET /api/webhooks): recognise the endpoint from
     * the path. Returns [method, webhook id] or null.
     */
    public static function endpointFromPath(Request $request)
    {
        if (!preg_match('#(?:^|/)api/webhooks(?:/([^/]+))?/?$#', $request->path(), $matches)) {
            return null;
        }

        $id = $matches[1] ?? null;
        $http_method = $request->getMethod();

        if ($id === null && in_array($http_method, ['GET', 'HEAD'])) {
            return ['listWebhooks', null];
        }
        if ($id === null && $http_method == 'POST') {
            return ['createWebhook', null];
        }
        if ($id !== null && $http_method == 'DELETE') {
            return ['deleteWebhook', $id];
        }

        return null;
    }

    public static function handle($method, Request $request, $webhook_id, User $user, Authorization $authorization)
    {
        if (!self::available()) {
            return ApiResponse::error('Webhooks are not available.', 503);
        }

        switch ($method) {
            case 'listWebhooks':
                return self::listWebhooks($authorization);
            case 'createWebhook':
                return self::createWebhook($request, $user, $authorization);
            case 'deleteWebhook':
                return self::deleteWebhook($webhook_id, $authorization);
        }

        return ApiResponse::notFound();
    }

    protected static function listWebhooks(Authorization $authorization)
    {
        $links = OAuthWebhook::where('authorization_id', $authorization->id)->orderBy('webhook_id')->get();
        $webhooks = \Webhook::whereIn('id', $links->pluck('webhook_id')->all())->get()->keyBy('id');

        $items = [];
        foreach ($links as $link) {
            if (isset($webhooks[$link->webhook_id])) {
                $items[] = self::format($webhooks[$link->webhook_id], $link);
            }
        }

        return ApiResponse::json([
            '_embedded' => ['webhooks' => $items],
            'page'      => [
                'size'          => count($items),
                'totalElements' => count($items),
                'totalPages'    => 1,
                'number'        => 1,
            ],
        ]);
    }

    protected static function createWebhook(Request $request, User $user, Authorization $authorization)
    {
        if (OAuthWebhook::where('authorization_id', $authorization->id)->count() >= self::MAX_PER_AUTHORIZATION) {
            return ApiResponse::badRequest('This application already has the maximum of '.self::MAX_PER_AUTHORIZATION.' webhooks.', 'url');
        }

        // URL.
        $url = $request->input('url');
        if (!is_string($url) || strlen($url) > 255 || !filter_var($url, FILTER_VALIDATE_URL)
            || !in_array(strtolower((string) parse_url($url, PHP_URL_SCHEME)), ['http', 'https'])
        ) {
            return ApiResponse::badRequest('`url` must be an http or https URL of at most 255 characters.', 'url');
        }
        if (!self::isSafeUrl($url)) {
            return ApiResponse::badRequest('This webhook address is not allowed: it points to the FreeScout server or a private network. An administrator can allow hosts with APP_REMOTE_HOST_WHITE_LIST.', 'url');
        }

        // Events.
        $events = self::stringList($request->input('events'));
        if (!$events) {
            return ApiResponse::badRequest('`events` parameter is required', 'events');
        }
        $known = \Webhook::getAllEvents();
        foreach ($events as $event) {
            if (!in_array($event, $known, true)) {
                return ApiResponse::badRequest('Unknown event: '.$event, 'events');
            }
            if (self::isCustomerEvent($event) && Access::customersLimited($user)) {
                return ApiResponse::badRequest('Customer events are not available: customer visibility is limited for your account.', 'events');
            }
        }

        // Mailboxes: optional, and only ones the user can see.
        $requested = null;
        $mailboxes_input = $request->has('mailboxes') ? $request->input('mailboxes') : $request->input('mailboxIds');
        if ($mailboxes_input !== null && $mailboxes_input !== '' && $mailboxes_input !== []) {
            $requested = array_values(array_unique(array_map('intval', self::stringList($mailboxes_input))));
            $accessible = Access::mailboxIds($user);
            foreach ($requested as $mailbox_id) {
                if (!in_array($mailbox_id, $accessible, true)) {
                    return ApiResponse::badRequest('Mailbox not found: '.$mailbox_id, 'mailboxes');
                }
            }
        }

        $webhook = new \Webhook();
        $webhook->url = $url;
        $webhook->events = $events;
        $webhook->mailboxes = self::effectiveMailboxes($user, $requested);
        $webhook->save();

        $link = new OAuthWebhook();
        $link->webhook_id = $webhook->id;
        $link->authorization_id = $authorization->id;
        $link->user_id = $user->id;
        $link->mailbox_ids = $requested;
        $link->created_at = now();
        $link->save();

        self::clearCache();

        $response = ApiResponse::json(self::format($webhook, $link), 201);
        $response->headers->set('Resource-ID', $webhook->id);

        return $response;
    }

    protected static function deleteWebhook($webhook_id, Authorization $authorization)
    {
        if (!is_scalar($webhook_id) || !ctype_digit((string) $webhook_id)) {
            return ApiResponse::notFound();
        }

        // Webhooks of other applications, and those made in the
        // FreeScout settings, are "not found".
        $link = OAuthWebhook::where('authorization_id', $authorization->id)
            ->where('webhook_id', (int) $webhook_id)
            ->first();

        if (!$link) {
            return ApiResponse::notFound();
        }

        self::deleteLinked($link);

        return ApiResponse::json([], 204);
    }

    /**
     * Runs before the API & Webhooks module delivers an event (Eventy
     * action "webhook.run", at a lower priority number so it runs first).
     *
     * An action cannot be cancelled, so a delivery is stopped by narrowing
     * the webhook's mailbox list, which the API & Webhooks module checks
     * right after this. That works for conversation events. A customer
     * event cannot be stopped that way: the webhook is fixed so it does
     * not happen again, and this delivery is stopped with an exception.
     */
    public static function guardDelivery($webhook, $event, $data)
    {
        if (!$webhook || empty($webhook->id)) {
            return;
        }

        $link = OAuthWebhook::where('webhook_id', $webhook->id)->first();
        if (!$link) {
            // Not created through OAuth, or deleted since this delivery was
            // queued: the queued job carries a copy of the webhook, so
            // check it still exists.
            if (!\Webhook::where('id', $webhook->id)->exists()) {
                self::stop($webhook, $data, 'it has been deleted');
            }

            return;
        }

        $authorization = $link->authorization;
        if (!$authorization || !$authorization->isUsable()
            || !Access::apiAllowed($authorization->user)
            || !in_array(Scopes::WEBHOOKS, $authorization->effectiveScopes())
        ) {
            // The application lost access: the webhook goes for good.
            self::deleteLinked($link);
            self::stop($webhook, $data, 'its application no longer has access');

            return;
        }

        $user = $authorization->user;

        // Checked again at delivery: DNS can point somewhere else by now.
        if (!self::isSafeUrl($webhook->url)) {
            self::deleteLinked($link);
            self::stop($webhook, $data, 'its address now points to the FreeScout server or a private network');

            return;
        }

        if ($data instanceof Conversation) {
            $requested = $link->requestedMailboxIds();
            $visible = Access::canViewConversation($user, $data)
                && ($requested === null || in_array((int) $data->mailbox_id, $requested, true));

            // When visible, also refresh the stored mailbox list to the
            // user's current access, so it stays right even if this module
            // is switched off later.
            $webhook->mailboxes = $visible ? self::effectiveMailboxes($user, $requested) : [0];

            return;
        }

        if ($data instanceof Customer) {
            if (!Access::customersLimited($user) || Access::canViewCustomer($user, $data)) {
                return;
            }
            // Customer visibility became limited after the webhook was
            // made: drop its customer events.
            self::removeCustomerEvents($webhook);
            self::stop($webhook, $data, 'customer visibility is limited for its user');

            return;
        }

        // Anything else (e.g. events from other modules) only reaches
        // webhooks of administrators.
        if (!$user->isAdmin()) {
            self::stop($webhook, $data, 'event "'.$event.'" is only available to administrators');
        }
    }

    /**
     * Delete every webhook of an authorization (when it is revoked).
     */
    public static function deleteForAuthorization(Authorization $authorization)
    {
        if (!\Schema::hasTable('oauthapi_webhooks')) {
            return;
        }

        foreach (OAuthWebhook::where('authorization_id', $authorization->id)->get() as $link) {
            self::deleteLinked($link);
        }
    }

    protected static function deleteLinked(OAuthWebhook $link)
    {
        if (self::available()) {
            \Webhook::where('id', $link->webhook_id)->delete();
            self::clearCache();
        }
        $link->delete();
    }

    /**
     * The list stored on the webhook itself: the requested mailboxes the
     * user can see, or all of them. [] means "every mailbox" to the
     * API & Webhooks module, which only an administrator may have; [0]
     * matches no mailbox.
     */
    protected static function effectiveMailboxes(User $user, $requested)
    {
        if ($requested === null && $user->isAdmin()) {
            return [];
        }

        $accessible = Access::mailboxIds($user);
        $ids = $requested === null ? $accessible : array_values(array_intersect($requested, $accessible));

        return $ids ?: [0];
    }

    protected static function removeCustomerEvents($webhook)
    {
        $events = array_values(array_filter((array) $webhook->events, function ($event) {
            return !self::isCustomerEvent($event);
        }));

        // Write only the events column: the in-memory model is the one the
        // API & Webhooks module is about to use.
        \Webhook::where('id', $webhook->id)->update(['events' => json_encode($events)]);
        self::clearCache();
    }

    protected static function stop($webhook, $data, $reason)
    {
        if ($data instanceof Conversation) {
            $webhook->mailboxes = [0];

            return;
        }

        throw new WebhookSuppressed('[OAuthApi] Webhook '.$webhook->id.' was not sent: '.$reason.'.');
    }

    protected static function isCustomerEvent($event)
    {
        return strpos((string) $event, 'customer.') === 0;
    }

    protected static function format($webhook, OAuthWebhook $link)
    {
        $data = \ApiWebhooks::formatEntity($webhook);
        if (!is_array($data)) {
            $data = [
                'id'     => $webhook->id,
                'url'    => $webhook->url,
                'events' => $webhook->events,
            ];
        }
        $data['mailboxes'] = $link->requestedMailboxIds();

        // The delivery error can quote the receiving server's response;
        // with a webhook pointed at an internal address that would be a
        // way to read it.
        unset($data['lastRunError']);

        return $data;
    }

    /**
     * FreeScout's own SSRF check (\Helper::checkUrlHost): refuses the
     * FreeScout server itself, private and reserved networks and cloud
     * metadata addresses, unless an administrator allowed the host in
     * APP_REMOTE_HOST_WHITE_LIST. Non-admin users can create OAuth
     * webhooks, so this matters more than for the master key.
     */
    protected static function isSafeUrl($url)
    {
        if (!method_exists('\Helper', 'checkUrlHost')) {
            // Older FreeScout: at least keep out private and reserved
            // networks.
            $host = trim((string) parse_url($url, PHP_URL_HOST), '[]');
            $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : (gethostbynamel($host) ?: []);
            foreach ($ips as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return false;
                }
            }

            return (bool) $ips;
        }

        try {
            return (bool) \Helper::checkUrlHost($url);
        } catch (\Throwable $e) {
            return false;
        }
    }

    protected static function clearCache()
    {
        if (method_exists('\ApiWebhooks', 'clearWebhooksCache')) {
            \ApiWebhooks::clearWebhooksCache();
        }
    }

    /**
     * "a,b" or ["a", "b"] as a list of non-empty strings.
     */
    protected static function stringList($value)
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (!is_array($value)) {
            $value = explode(',', (string) $value);
        }

        $list = [];
        foreach ($value as $item) {
            if (is_scalar($item) && trim((string) $item) !== '') {
                $list[] = trim((string) $item);
            }
        }

        return array_values(array_unique($list));
    }
}
