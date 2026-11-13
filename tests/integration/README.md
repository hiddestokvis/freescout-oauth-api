# Integration tests

A disposable FreeScout (PHP 8.2, MariaDB in memory) with the API & Webhooks
module and this module, and an end-to-end test suite that drives the real
OAuth flow in the browser's place and calls the API as users with
different access.

## Run

The API & Webhooks module is a paid FreeScout module and is not part of
this repository. Point `APIWEBHOOKS_PATH` at your copy of
`Modules/ApiWebhooks`:

```
cd tests/integration
export APIWEBHOOKS_PATH=/path/to/Modules/ApiWebhooks
docker compose -p oauthapi-test up -d --build
python3 run_tests.py
docker compose -p oauthapi-test down
```

Tested with API & Webhooks 1.0.87 (122 checks) and 1.0.116 (132 checks:
the extra ones cover the "access API" permission and endpoints added in
1.0.11x). FreeScout runs on http://localhost:8088 (change with `HOST_PORT`). The
tests expect a fresh stack: run `down` and `up` again before re-running.
Python 3 standard library only; the tests run commands in the container
through `docker compose exec`.

## What is covered

- Registering confidential and public applications in the settings page.
- Authorization request errors (unknown client, wrong redirect URI, bad
  scope, missing PKCE, `prompt=none`, user cancels, not logged in).
- Code exchange: PKCE, redirect URI binding, client authentication, code
  replay revoking its tokens, skipping consent when already authorized.
- The API as an administrator, users with access to one mailbox, a user
  limited to assigned conversations, and users with and without the
  delete-conversations and manage-users permissions: lists, single
  records, writes, assignment and move rules, identity pinning, spelling
  variants of fields, scopes.
- Webhooks: per-application listing and deleting, and delivery only for
  the user's mailboxes (checked in the receiver's log).
- Refresh token rotation, narrowing, reuse detection; revocation endpoint;
  revoking from the Authorized Apps page (tokens and webhooks); disabling
  an application and removing a scope from it.
- Limited customer visibility, and the `OAUTHAPI_DISABLED` switch.

## Files

- `Dockerfile`, `entrypoint.sh`, `docker-compose.yml`: the FreeScout
  container. The entrypoint installs FreeScout, copies both modules in and
  starts a webhook receiver on port 9000 that writes to `/tmp/webhooks.log`.
- `seed.php`: activates the modules, creates two mailboxes and five users.
- `php_eval.php`: runs PHP inside FreeScout for checks, and drains the
  webhook queue.
- `run_tests.py`: the tests.
