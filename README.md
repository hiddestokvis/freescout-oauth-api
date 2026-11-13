# OAuth API for FreeScout

> **Beta (0.1.0).** Tested end to end against FreeScout 1.8.250 with
> API & Webhooks 1.0.87 and 1.0.116, but not yet used in production. Try
> it on a staging instance first and report problems as issues.

FreeScout's [API & Webhooks module](https://freescout.net/module/api-webhooks/)
has one API key for the whole instance, and that key can do everything:
every mailbox, every conversation, creating and deleting users.

This module lets applications connect to that same API with **OAuth 2.0**
instead. A user logs in to FreeScout, approves the application, and the
application gets a token that **acts as that user**: it can only see and
do what the user can see and do in FreeScout, limited further by the
scopes the user approved.

- **Same API.** Tokens work on the existing endpoints
  ([api-docs.freescout.net](https://api-docs.freescout.net/)) with
  `Authorization: Bearer <token>`. No second API to learn or maintain.
- **The user's access level, on every request.** Mailbox access, the "see
  only assigned conversations" restriction, the delete-conversations and
  manage-users permissions, limited customer visibility, admin or not, all
  checked live. Taking a mailbox away from a user takes effect on the next
  request.
- **Acts as the user, never as someone else.** Notes, replies, status
  changes and assignments are recorded as the token's user, whatever user
  ID the request names.
- **Scopes** on top: an application only gets the parts of the API it
  asked for and the user approved.
- **Webhooks per application**, delivered only for conversations its user
  can see.
- **Standard OAuth**: authorization code flow with PKCE, rotating refresh
  tokens with reuse detection, token revocation, server metadata. Works
  with any OAuth 2.0 client library.
- **Users stay in control**: "Authorized Apps" on their profile lists every
  connected application, with a Revoke button.

It does not modify FreeScout or the API & Webhooks module, and the master
API key keeps working exactly as before.

## Requirements

- FreeScout 1.8.198 or newer.
- The **API & Webhooks** module, installed and active. Tested with
  1.0.87 and 1.0.116.

API & Webhooks 1.0.11x added personal API keys ("My API Keys") that also
act as their user. This module adds what those don't have: applications
that users connect with a login and consent screen instead of copying a
key, per-application scopes, expiring tokens, per-application revocation,
and webhooks for non-admin users. On 1.0.11x, OAuth requests also go
through API & Webhooks' own per-user checks, on top of this module's (see
docs/DESIGN.md), and its "Users are allowed to access API" permission
applies: users without it cannot connect applications.

## Install

1. Copy the `OAuthApi` folder into FreeScout's `Modules` directory, with
   the same ownership and permissions as your other modules.
2. Activate **OAuth API** on the Modules page.
3. Create the module's tables: **Manage » System » Migrate DB** (or
   `php artisan migrate --force`).
4. Open **Manage » Settings » OAuth Apps**.

## Registering an application

On **Manage » Settings » OAuth Apps**, an administrator registers each
application:

- **Name**: shown to users on the consent screen.
- **Redirect URIs**: where users are sent back to, one per line, matched
  exactly. `https`, or `http` only for `127.0.0.1`, `[::1]` and `localhost`
  (any port, for desktop and command line apps). Private-use schemes such
  as `com.example.app:/callback` work for mobile apps.
- **Allowed scopes**: the most the application can ask for.
- **Type**: *Confidential* for server-side applications that can keep a
  secret; *Public* for browser, desktop, mobile and command line
  applications. Public applications have no secret and must use PKCE.

The client ID and, for confidential applications, the client secret are
shown once. Each application can later be disabled (its tokens stop
working), given a new secret, disconnected from all users, or deleted.

The same page lists the endpoint URLs and the token lifetimes (access
tokens: 60 minutes by default; refresh tokens: 30 days).

## Scopes

| Scope | Endpoints |
|---|---|
| `conversations.read` | list and get conversations, list time logs |
| `conversations.write` | create and update conversations, add replies and notes, update tags and custom fields, add time logs |
| `conversations.delete` | delete conversations (forever) |
| `customers.read` | list and get customers |
| `customers.write` | create and update customers and customer fields |
| `mailboxes.read` | list mailboxes, their folders and custom fields |
| `tags.read` | list tags |
| `users.read` | list and get users |
| `users.write` | create and delete users (administrators only) |
| `reports.read` | reports (administrators only) |
| `webhooks` | list, create and delete the application's own webhooks |

`GET /api/users/me` (API & Webhooks 1.0.11x) works with any scope.

A scope never gives more than the user has: `conversations.delete` does
nothing for a user without the "delete conversations" permission, and
`users.write` and `reports.read` only work for administrators.

## What a token can see and do

The token's user is checked against FreeScout's own rules on every
request:

| | Administrator | Other users |
|---|---|---|
| Conversations | all | in their mailboxes (archived ones excluded); only assigned to or created by them if they have the "see only assigned conversations" restriction |
| Replies, notes, status, assignment | recorded as the user | recorded as the user; assignees must have access to the mailbox; moving needs access to both mailboxes |
| Delete conversations | yes | with the "delete conversations" permission |
| Customers | all | all, or only those with a conversation in their mailboxes when "limit user customer visibility" is on |
| Mailboxes | all | their own |
| Users | all | those who share a mailbox with them |
| Create users | yes | no |
| Delete users | yes (not themselves) | no |
| Time logs | all | of their conversations; only their own when filtering by or booking for a user |
| Reports | yes | no |
| Use the API at all (1.0.11x) | yes | with the "Users are allowed to access API" permission |

Records a user cannot see answer **404 Not Found**, so their existence is
not revealed. A missing scope answers **403** with
`WWW-Authenticate: Bearer error="insufficient_scope"`. An invalid, expired
or revoked token answers **401**.

## For application developers

The server publishes its configuration at
`/.well-known/oauth-authorization-server` (also `/oauth/metadata`), so most
OAuth libraries only need the FreeScout URL, the client ID and the secret.

1. Send the user to the authorization endpoint:

   ```
   https://freescout.example.com/oauth/authorize
       ?response_type=code
       &client_id=fsc_...
       &redirect_uri=https://app.example.com/callback
       &scope=conversations.read conversations.write
       &state=<random>
       &code_challenge=<S256 challenge>
       &code_challenge_method=S256
   ```

   The user logs in (if needed) and approves. They come back to the
   redirect URI with `code`, `state` and `iss`. For confidential
   applications, a user who already approved these scopes is sent straight
   back (pass `prompt=consent` to always ask); public applications always
   show the consent screen. PKCE (`S256` only) is required for public clients and
   recommended for all.

2. Exchange the code (HTTP Basic auth with the client ID and secret, or
   `client_id`/`client_secret` in the body; public clients send only
   `client_id`):

   ```
   curl -u fsc_...:fscs_... https://freescout.example.com/oauth/token \
     -d grant_type=authorization_code -d code=... \
     -d redirect_uri=https://app.example.com/callback -d code_verifier=...
   ```

   ```json
   {"access_token": "fsat_...", "token_type": "Bearer", "expires_in": 3600,
    "refresh_token": "fsrt_...", "scope": "conversations.read conversations.write"}
   ```

3. Call the API:

   ```
   curl -H "Authorization: Bearer fsat_..." https://freescout.example.com/api/conversations
   ```

   Tools that only support FreeScout's API key can put the access token in
   the `X-FreeScout-API-Key` header instead.

4. Refresh before or after the access token expires:
   `grant_type=refresh_token&refresh_token=fsrt_...`. Every refresh returns
   a **new refresh token**; the old one stops working. Presenting an old
   refresh token again is treated as theft: every token of that
   authorization is revoked and the user must approve again. Do not run
   refreshes in parallel with the same refresh token.

Other endpoints:

- `POST /oauth/revoke` (RFC 7009): revoke an access or refresh token.
- `GET /oauth/userinfo` with the bearer token: who the token belongs to.

Fields that name who performs an action are always set to the token's
user: `byUser` on conversation updates, `user` on threads, `byUserId` when
deleting users. They can be left out.

### Webhooks

`POST /api/webhooks` with `url`, `events` and optionally `mailboxes` (IDs
the user can see) creates a webhook owned by the application;
`GET /api/webhooks` lists only the application's own webhooks and
`DELETE /api/webhooks/{id}` deletes one of them. They are ordinary
API & Webhooks webhooks (same payload, signature and retries) and appear
in the API & Webhooks settings too.

Webhook URLs must not point at the FreeScout server, private networks or
cloud metadata addresses (FreeScout's own SSRF check). An administrator
can allow specific hosts with `APP_REMOTE_HOST_WHITE_LIST` in `.env`.
The list response leaves out the delivery error text.

Before each delivery the event is checked against the user's access at
that moment: an event about a conversation the user cannot see is not
sent. When the user revokes the application, is deleted or disabled, or
the application is disabled, its webhooks are deleted. Customer events are
not available to users with limited customer visibility.

## Security notes

- Tokens, codes and client secrets are stored only as HMAC-SHA256 hashes
  keyed with `APP_KEY`.
- The consent page cannot be framed. After approval the browser is
  forwarded with a small page rather than a redirect, so FreeScout's
  Content Security Policy (`form-action 'self'`) does not block the
  return to the application.
- Endpoints added by future API & Webhooks versions are refused to OAuth
  tokens until this module knows how to check them, and the refusal is
  logged.
- Webhook addresses are checked when created and again before every
  delivery, but the HTTP client follows redirects, so a receiver could
  still bounce a delivery to an internal address. Only give the `webhooks`
  scope to applications you trust.
- All webhooks share one signing secret (an API & Webhooks design). A
  signed payload an application receives could be replayed to another
  receiver that trusts the same `X-FreeScout-Signature`; receivers
  should not rely on the signature alone to tell webhooks apart.
- Failed deliveries are retried by API & Webhooks for about 90 minutes
  without the access check. Only payloads that passed it the first time
  are retried, and retries stop when the webhook is deleted.
- Users can see other users who share a mailbox with them (name, email,
  phone, role), as in FreeScout's assignee lists. That is more than
  FreeScout's profile pages show (only yourself, or everyone for
  administrators); leave `users.read` out of an application's scopes if
  that matters.
- The access token can be sent as the `api_key` query parameter for
  compatibility, but then it ends up in server logs. Prefer the header.

## Older API & Webhooks versions

The module checks every request itself and does not depend on the hooks
of a particular API & Webhooks version: list queries are limited to what
the user can see with a temporary database scope, so results and page
counts are exact on any version. List responses are also filtered after
the controller ran, as a safety net; if that ever removes anything, the
FreeScout log says so.

## Emergency switch

Set `OAUTHAPI_DISABLED=true` in FreeScout's `.env` file to switch the
module off without uninstalling it: OAuth tokens stop working at once,
nobody can authorize applications, and the master key keeps working.
Webhooks created through OAuth are still checked before every delivery.

Deactivating the module on the Modules page also stops OAuth tokens, but
nothing checks webhook deliveries any more: webhooks created through OAuth
then get every event of the mailboxes stored on them. Before uninstalling,
disconnect the applications (or delete their webhooks in the
API & Webhooks settings).

## Command line

```
php artisan oauthapi:purge
```

Deletes expired codes and tokens. Runs daily through FreeScout's
scheduler.

## Using it with API Key Manager

Works side by side with
[API Key Manager](https://github.com/ShowDotFM/freescout-api-key-manager):
its `fskey_` keys and this module's `fsat_` tokens do not interfere.

## Tests

See [tests/integration/README.md](tests/integration/README.md): a
disposable FreeScout in Docker and an end-to-end test suite.

## License

AGPL-3.0, the same as FreeScout.
