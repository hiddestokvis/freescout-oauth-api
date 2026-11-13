# Design

Why the module is built the way it is, what it depends on, and what to
check after FreeScout or API & Webhooks updates. Read this before
changing anything in `Http/Middleware`, `Support/EndpointGuard.php`,
`Support/Access.php` or `Support/WebhookManager.php`.

## 1. The problem

The API & Webhooks module authenticates with one instance-wide key
(`md5(APP_KEY.'api_key'.salt)`, compared in its `ApiAuth` route
middleware). Its controller has no notion of "the current user": requests
name the acting user in fields (`byUser`, `threads[].user`, `byUserId`),
and every endpoint sees every mailbox. Webhooks are instance-wide too,
filtered only by an optional mailbox list.

Goal: let third-party applications use that API on behalf of a FreeScout
user, limited to what that user may do, without modifying FreeScout or
API & Webhooks, and without breaking the master key.

## 2. Options considered

1. **A separate API module** (own routes and controllers). Full control,
   but it duplicates a large API that keeps evolving, and integrations
   built for the official API would not work with it.
2. **Bridge onto the existing API** (chosen). Validate the OAuth token,
   check the request against the user's permissions, then let the
   API & Webhooks controller run it as a master-key request. Same API,
   same payloads, same docs.

The bridge is only safe if every request can be checked *before* the
controller runs. That turned out to be possible for every endpoint; see
section 4.

## 3. Request flow

```
request with "Authorization: Bearer fsat_..."
  │
  ▼
AuthenticateOAuthToken (global middleware, prepended: runs before routing)
  │  1. token valid? authorization not revoked? app enabled? user active?  → else 401
  │  2. match the route ourselves (router->getRoutes()->match())          → unknown: 404/405
  │     route must be ApiWebhooks ApiController                           → else 403
  │  3. method → scope (Scopes::$endpoints); unmapped method              → 403, logged
  │  4. token's effective scopes include it?                              → else 403 insufficient_scope
  │  5. webhooks endpoints: answered here (WebhookManager), never reach the controller
  │  6. EndpointGuard::check(): records in the URL, fields in the body    → 404 / 403 / 400
  │  7. swap in the live master key (header + api_key input), set request attributes
  │  8. on 1.0.11x: attach an in-memory personal API key for the user, log the user in
  │     for this request (actAsUser)
  ▼
ApiAuth (API & Webhooks, untouched): key matches
  │  api.auth.allowed filter: route method must equal the checked one (when the hook exists)
  ▼
ApiController: list endpoints run under a temporary Eloquent global scope (ListScopes);
  │            api.*.query / api.*.find filters narrow queries too (when the hooks exist)
  ▼
ListFilter (back in the middleware): drop list items the user cannot see (safety net)
```

Nothing is swapped until every check passed. An exception anywhere
returns 500; a request is never let through unchecked.

Effective scopes = token scopes ∩ the authorization's scopes ∩ the scopes
the application is currently allowed. An administrator removing a scope
from an application takes effect on the next request.

## 4. The checks (EndpointGuard)

Three techniques:

- **Records in the URL** are loaded with `Model::find($raw_param)`, exactly
  as the controller does (so both resolve `"5abc"` the same way), and
  checked with FreeScout's own policies (`ConversationPolicy::view/update/
  delete`, `CustomerPolicy::view`, `UserPolicy::create/delete`) or the same
  rules (`hasAccessToMailbox`, `whichUsersCanView`). Not visible → 404.
- **Identity fields are pinned** to the token's user: `byUser`,
  `threads[].user`, thread `user`, `byUserId`. Callers cannot act as
  someone else, and need not send these fields.
- **Reference fields are validated**: a target mailbox (create, move),
  an assignee (must have access to the mailbox; the controller does not
  check this), a customer by ID (must be visible). List filters are
  narrowed in the request (`mailboxId`, `userId`) so page counts stay
  exact even without the query hooks.

**Snake-case collisions.** The controller runs `Str::snake()` over request
keys before reading most of them, so `mailboxId`, `MailboxId` and
`mailbox_id` all become `mailbox_id` and the last one wins. A guard that
checks `mailboxId` while the controller reads `MailboxId` would be
bypassed. So for endpoints where fields are checked, a request in which
two keys collapse into the same snake-case name (at any depth) is refused
with 400, and fields are found by their snake-case name, whatever their
spelling. The integration tests cover this.

**Raw input.** The middleware is prepended, so it runs before FreeScout's
`TrimStrings` and `ConvertEmptyStringsToNull`: it sees `"\u00005"`, the
controller sees `"5"`. IDs in the request body are therefore accepted
only as plain digits (`findStrict`), and an ID that names no record is
refused rather than let through. Route parameters are not trimmed and are
loaded exactly as the controller loads them.

**Customer objects.** `createConversation` unwraps `customer[0]` (when not
empty) and `createThread` never does; a customer object that mixes `0`
with other keys is refused, so the guard and the controller always read
the same ID.

`createUser` by a non-administrator keeps only an allowlist of profile
fields: `User::setData()` mass-assigns, and `permissions` or `status`
would otherwise go straight through.

## 4b. API & Webhooks 1.0.11x personal keys

1.0.11x added personal API keys (`fs_...`, table `api_keys`). For those,
ApiAuth logs the owner in (`Auth::onceUsingId`) and sets the request
attribute `user_api_key`; the controller then checks mailbox access,
`can('view')`, `byUser`/`user` equal to the owner, and admin-only rules
(users, webhooks, reports, other users' time logs) itself.

The middleware reuses that as a second layer: after its own checks it
sets `user_api_key` to an unsaved `ApiKey` for the token's user (ability
read or write from the scopes, no mailbox limit) and logs the user in with
`Auth::setUser()`. ApiAuth only touches the attribute for non-master keys,
and nothing in the controller saves the key. This module's checks stay in
front, so either layer alone keeps a token within its user's access.

The same version added the user permission `api.access` ("Users are
allowed to access API"); without it non-admins get 403, cannot authorize
applications, and their applications' webhooks are deleted.

Notable 1.0.11x endpoints: `getMe` (no scope), `listConversationTimelogs`
and `createTimelog`, a global `listTimelogs` (limited by ListScopes to the
user's conversations), and `getReport`, which logs in as the first
administrator when nobody is logged in: mapped to `reports.read` and
refused to non-admins before the controller runs.

## 5. Lists

Layers, so lists are right on any API & Webhooks version:

1. Request narrowing in EndpointGuard (conversations by mailbox, mailboxes
   by user).
2. `ListScopes`: for the duration of a list request, an Eloquent global
   scope on the listed model (Conversation, Customer, User, Mailbox) with
   the user's visibility rules. The controller's query and its page count
   both go through it, so counts are exact and filter parameters
   (`?subject=`, `?email=`) cannot be used to count hidden records. The
   allowed IDs are computed before the scope is added (they come from
   queries on the same models), and the scope is removed right after the
   controller answered. Only the read-only list endpoints use it.
3. `api.*.query` filters, where those hooks exist.
4. `ListFilter`, after the controller: removes any item the user cannot
   see. It should never remove anything; if it does, it logs that once a
   day.

## 6. Webhooks

API & Webhooks webhooks are instance-wide. For OAuth tokens the module
answers `GET/POST /api/webhooks` and `DELETE /api/webhooks/{id}` itself
(also when the API & Webhooks version lacks the route), scoped to the
authorization. A created webhook is a normal row in `webhooks` (so
signing, delivery, retries and logs stay with API & Webhooks), linked in
`oauthapi_webhooks` to the authorization and the requested mailboxes.

Delivery is checked at the moment it happens: a `webhook.run` action at
priority 10 runs before the API & Webhooks handler at priority 20, in the
queue worker. An Eventy action cannot be cancelled, so:

- **Conversation events**: the handler skips a webhook whose `mailboxes`
  list does not contain the conversation's mailbox. The guard sets the
  in-memory list to `[0]` when the user cannot see the conversation (no
  save happens: the delivery is skipped), and otherwise to the user's
  current mailboxes. That list is saved by `Webhook::run()`, keeping the
  stored value close to the user's access in case the module is ever
  switched off.
- **Customer events** cannot be stopped that way. They are refused at
  creation for users with limited customer visibility. If that changes
  later (setting turned on, admin demoted), the guard removes the
  customer events from the webhook and throws `WebhookSuppressed` for
  that one delivery.
- **App lost access** (revoked, user deleted or disabled, app disabled,
  scope removed): the webhook is deleted. Revoking an authorization or
  disabling an application deletes its webhooks straight away.
- **Already queued deliveries**: the queued job holds a serialized copy of
  the webhook, not a reference. When the webhook no longer exists (no
  `oauthapi_webhooks` link and no `webhooks` row), the delivery is stopped
  as above.
- **Webhook addresses** go through `\Helper::checkUrlHost()` (FreeScout's
  SSRF check, with `APP_REMOTE_HOST_WHITE_LIST`) on creation and again
  before every delivery. Redirects followed by Guzzle are not checked.
  `lastRunError` is left out of the API response.

Retries of failed deliveries (`freescout:webhooks-process`) call
`Webhook::run()` directly, without the action. They only retry payloads
that passed the guard before, and stop when the webhook is deleted.

## 7. OAuth details

- Authorization code grant only, with PKCE `S256` (required for public
  clients). No implicit or password grant.
- Codes: 10 minutes, single use (atomic `used_at` update); reuse revokes
  the tokens the code produced. Redirect URI must be repeated in the token
  request if it was sent in the authorization request.
- Refresh tokens rotate (atomic `rotated_at` update). A rotated refresh
  token presented again revokes every token of the authorization (OAuth
  2.1 / RFC 6819 replay detection). Scope can be narrowed on refresh,
  never widened.
- One authorization per (application, user). Scopes add up across
  consents; revoking resets them. Already-covered requests from
  confidential clients skip the consent screen unless `prompt=consent`;
  public clients always get it (a loopback redirect port can be taken by
  any local program, RFC 8252 section 8.6). `prompt=none` returns
  `consent_required` instead of showing it.
- Redirect URIs match exactly; loopback URIs match on any port (RFC 8252).
- After the consent form the browser is forwarded with a meta-refresh
  page, not a 302: FreeScout's CSP has `form-action 'self'`, and browsers
  apply it to redirects that follow a form post (the consent form, or the
  login form when the user was logged out). Errors about the client or
  redirect URI are shown, never redirected.
- `iss` is added to the authorization response (RFC 9207). Metadata at
  `/.well-known/oauth-authorization-server` (RFC 8414) and
  `/oauth/metadata`.
- Tokens: `fsat_` / `fsrt_` + 64 hex chars from `random_bytes`, stored as
  `hash_hmac('sha256', token, APP_KEY)`. Changing `APP_KEY` invalidates
  them, as it does every FreeScout session.

## 8. Fragility register

Contracts the module relies on. Check after FreeScout or API & Webhooks
updates; run the integration tests.

| Dependency | If it changes |
|---|---|
| `\ApiWebhooks::getApiKey()` | swap fails → OAuth requests 401 (fail closed) |
| `ApiAuth` reads `api_key` input, then `X-FreeScout-API-Key` header | same |
| Route action `Modules\ApiWebhooks\Http\Controllers\ApiController@method` | namespace change → all OAuth requests 403 (fail closed) |
| ApiController method names (`Scopes::$endpoints`) | new or renamed endpoints → 403 until mapped (fail closed, logged). Checked against 1.0.116 |
| `user_api_key` attribute, `ApiKey` (1.0.11x) | the native second layer lapses; this module's checks still apply |
| `ApiKey::isApiAccessible()` / `api.access` permission | OAuth stops honouring the permission (fail open for that rule only) |
| Field names read by the controller (`byUser`, `user`, `byUserId`, `mailboxId`/`mailbox_id`, `assignTo`/`assign_to`, `customerId`, `customer.id`, `threads`) | a new identity or reference field would not be checked: review EndpointGuard against every API & Webhooks update |
| `ApiController::toSnake()` key renaming | covered by collision refusal and snake-case lookup |
| `webhook.run` action, priority 20, checking `$webhook->mailboxes` for `App\Conversation` | webhook guard lapses: **fail open for OAuth webhooks**. Test 'Alice's webhook: only the mailbox A event' catches it |
| `api.*.query` / `api.*.find` / `api.auth.allowed` filters | none in practice: ListScopes and ListFilter cover lists, the middleware's own route match covers dispatch |
| Eloquent `HasGlobalScopes::$globalScopes` (ListScopes) | lists fall back to ListFilter (safe, counts approximate) |
| `TrimStrings` / `ConvertEmptyStringsToNull` running after the middleware | covered by digits-only IDs in the body |
| `\Helper::checkUrlHost()` | fallback check refuses private and reserved IPs |
| FreeScout policies (`ConversationPolicy`, `CustomerPolicy`, `UserPolicy`), `mailboxesIdsCanView()`, `whichUsersCanView()`, `canSeeOnlyAssignedConversations()` | access rules follow FreeScout automatically |
| `Kernel::prependMiddleware` | boot failure, visible at once |
| `user.profile.menu.after_profile`, settings Eventy filters | UI entry points disappear |
| FreeScout CSP `form-action 'self'` | the forwarding page keeps working either way |

## 9. Limits and decisions

- Customers, tags and (for administrators) users are instance-wide in
  FreeScout's data model; the module follows FreeScout's own visibility
  rules for them, no more.
- `mailboxFolders` returns a mailbox's folders as the API does, including
  other users' personal folder entries (names and counts only).
- The kill switch keeps the webhook delivery guard running: it only ever
  holds deliveries back.
- Not implemented: dynamic client registration, token introspection,
  OpenID Connect, per-application rate limits, refresh token grace period
  for concurrent refreshes.
