#!/usr/bin/env python3
"""
Integration tests for the OAuth API module.

Runs the whole flow against the disposable FreeScout from docker-compose.yml:
registering applications, the authorization code flow with PKCE, tokens,
and the API as users with different access. Python standard library only.

    APIWEBHOOKS_PATH=/path/to/Modules/ApiWebhooks docker compose -p oauthapi-test up -d --build
    python3 run_tests.py

Exit code 0 when every check passes.
"""
import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get('BASE_URL', 'http://localhost:8088')
PROJECT = os.environ.get('COMPOSE_PROJECT', 'oauthapi-test')
HERE = os.path.dirname(os.path.abspath(__file__))
REDIRECT_URI = 'http://127.0.0.1:5555/callback'
ALL_SCOPES = ['conversations.read', 'conversations.write', 'conversations.delete', 'customers.read',
              'customers.write', 'mailboxes.read', 'tags.read', 'users.read', 'users.write', 'reports.read', 'webhooks']

failures = []
passes = 0


def check(name, condition, detail=''):
    global passes
    if condition:
        passes += 1
        print('  ok    ' + name)
    else:
        failures.append(name)
        print('  FAIL  ' + name + ('  -- ' + str(detail)[:400] if detail else ''))


def section(title):
    print('\n' + title)


# Docker helpers.

def compose(*args, user='www-data'):
    cmd = ['docker', 'compose', '-p', PROJECT, 'exec', '-T']
    if user:
        cmd += ['-u', user]
    cmd += ['app'] + list(args)
    return subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, check=True).stdout


def php(code):
    out = compose('php', '/tests/php_eval.php', code)
    return json.loads(out.strip().splitlines()[-1])


def drain_queue():
    return php('drain')


def webhook_log():
    out = compose('cat', '/tmp/webhooks.log', user=None)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def clear_webhook_log():
    compose('sh', '-c', ': > /tmp/webhooks.log', user=None)


def set_env(name, value):
    """Set a .env variable in the container and clear FreeScout's config cache."""
    compose('sh', '-c', "sed -i '/^%s=/d' .env && echo '%s=%s' >> .env && php artisan freescout:clear-cache >/dev/null" % (name, name, value))


def unset_env(name):
    compose('sh', '-c', "sed -i '/^%s=/d' .env && php artisan freescout:clear-cache >/dev/null" % name)


# HTTP helpers.

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def fetch(method, url, data=None, headers=None, opener=None):
    if not url.startswith('http'):
        url = BASE + url
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    opener = opener or urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(req, timeout=60)
        return Response(resp.status, resp.headers, resp.read().decode('utf-8', 'replace'), url)
    except urllib.error.HTTPError as e:
        return Response(e.code, e.headers, e.read().decode('utf-8', 'replace'), url)


class Browser:
    """A logged-in FreeScout session."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def request(self, method, url, fields=None, follow=True):
        data = urllib.parse.urlencode(fields, doseq=True).encode() if fields is not None else None
        headers = {'Content-Type': 'application/x-www-form-urlencoded'} if data else {}
        resp = fetch(method, url, data, headers, self.opener)
        hops = 0
        while follow and resp.status in (301, 302, 303) and hops < 10:
            location = urllib.parse.urljoin(resp.url, resp.headers['Location'])
            resp = fetch('GET', location, None, {}, self.opener)
            hops += 1
        return resp

    def get(self, url, follow=True):
        return self.request('GET', url, follow=follow)

    def post(self, url, fields, follow=True):
        return self.request('POST', url, fields, follow)

    def login(self, email):
        page = self.get('/login')
        resp = self.post('/login', {'_token': csrf(page.body), 'email': email, 'password': 'password123'})
        if '/login' in resp.url:
            raise RuntimeError('Login failed for ' + email)
        return self


def csrf(body):
    match = re.search(r'name="_token" value="([^"]+)"', body)
    return match.group(1) if match else ''


def api(token, method, path, body=None, via='bearer'):
    headers = {'Accept': 'application/json'}
    url = '/api' + path
    if via == 'bearer':
        headers['Authorization'] = 'Bearer ' + token
    elif via == 'header':
        headers['X-FreeScout-API-Key'] = token
    elif via == 'query':
        url += ('&' if '?' in url else '?') + 'api_key=' + urllib.parse.quote(token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    return fetch(method, url, data, headers)


def ids(resp, key):
    data = resp.json() or {}
    return sorted(item['id'] for item in data.get('_embedded', {}).get(key, []))


# OAuth helpers.

def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    return verifier, challenge


def register_client(admin, name, scopes, client_type='confidential', redirect_uris=REDIRECT_URI):
    page = admin.get('/app-settings/oauthapi')
    resp = admin.post('/oauth-api/clients', [
        ('_token', csrf(page.body)), ('action', 'create'), ('name', name), ('type', client_type),
        ('redirect_uris', redirect_uris),
    ] + [('scopes[]', s) for s in scopes])
    client_id = re.search(r'id="oauthapi-new-client-id"[^>]*value="([^"]*)"', resp.body)
    secret = re.search(r'id="oauthapi-new-client-secret"[^>]*value="([^"]*)"', resp.body)
    if not client_id:
        raise RuntimeError('Registering %s failed' % name)
    return {
        'name': name,
        'client_id': client_id.group(1),
        'secret': secret.group(1) if secret else None,
        'confidential': client_type == 'confidential',
    }


def parse_redirect_page(body):
    match = re.search(r'content="0;url=([^"]+)"', body)
    if not match:
        return None
    url = html.unescape(match.group(1))
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    query['_url'] = url
    return query


def authorize(browser, client, scopes, decision='approve', state=None, pkce=True, extra=None, redirect_uri=REDIRECT_URI):
    """Run the browser part of the flow. Returns the parameters the
    application would receive, plus _consent (was the consent screen shown)
    and _verifier."""
    verifier, challenge = pkce_pair()
    state = state or secrets.token_hex(8)
    params = {'response_type': 'code', 'client_id': client['client_id'], 'scope': ' '.join(scopes), 'state': state}
    if redirect_uri:
        params['redirect_uri'] = redirect_uri
    if pkce:
        params.update({'code_challenge': challenge, 'code_challenge_method': 'S256'})
    params.update(extra or {})

    resp = browser.get('/oauth/authorize?' + urllib.parse.urlencode(params))
    consent = 'name="decision"' in resp.body
    if consent:
        fields = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', resp.body))
        fields = {k: html.unescape(v) for k, v in fields.items()}
        fields['decision'] = decision
        resp = browser.post('/oauth/authorize', fields)

    result = parse_redirect_page(resp.body) or {'_status': resp.status, '_body': resp.body}
    result['_consent'] = consent
    result['_verifier'] = verifier
    result['_sent_state'] = state
    return result


def token_request(client, fields, basic=True):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    fields = dict(fields)
    if client['confidential'] and basic:
        creds = '%s:%s' % (urllib.parse.quote(client['client_id']), urllib.parse.quote(client['secret']))
        headers['Authorization'] = 'Basic ' + base64.b64encode(creds.encode()).decode()
    else:
        fields['client_id'] = client['client_id']
        if client['confidential']:
            fields['client_secret'] = client['secret']
    return fetch('POST', '/oauth/token', urllib.parse.urlencode(fields).encode(), headers)


def exchange(client, result, verifier=None, redirect_uri=REDIRECT_URI):
    fields = {'grant_type': 'authorization_code', 'code': result['code'], 'redirect_uri': redirect_uri}
    if verifier is not False:
        fields['code_verifier'] = verifier or result['_verifier']
    return token_request(client, fields)


def connect(browser, client, scopes):
    """Authorize and exchange; returns the token response JSON."""
    result = authorize(browser, client, scopes)
    resp = exchange(client, result)
    if resp.status != 200:
        raise RuntimeError('Token exchange failed: %s %s' % (resp.status, resp.body))
    return resp.json()


# The tests.

def main():
    fixtures = json.loads(compose('php', '/tests/seed.php').strip().splitlines()[-1])
    users = fixtures['users']
    mailboxes = fixtures['mailboxes']
    master = fixtures['master_key']

    def master_api(method, path, body=None):
        return api(master, method, path, body, via='header')

    def create_conversation(mailbox, email, subject, assign_to=None):
        body = {
            'type': 'email', 'mailboxId': mailbox, 'subject': subject, 'imported': True,
            'customer': {'email': email},
            'threads': [{'type': 'customer', 'text': subject, 'customer': {'email': email}}],
        }
        if assign_to:
            body['assignTo'] = assign_to
        resp = master_api('POST', '/conversations', body)
        if resp.status != 201:
            raise RuntimeError('Creating a conversation failed: %s %s' % (resp.status, resp.body))
        return resp.json()

    section('Fixtures')
    conv_a1 = create_conversation(mailboxes['a'], 'c1@example.com', 'A1 for Dave', users['dave'])
    conv_a2 = create_conversation(mailboxes['a'], 'c2@example.com', 'A2 for Carol', users['carol'])
    conv_b1 = create_conversation(mailboxes['b'], 'c3@example.com', 'B1 for Bob', users['bob'])
    customer_c3 = conv_b1['customer']['id']
    check('conversations created with the master key', conv_a1['id'] and conv_b1['id'])

    admin = Browser().login('admin@example.com')
    test_app = register_client(admin, 'Test App', ALL_SCOPES)
    cli = register_client(admin, 'CLI Tool', ['conversations.read', 'mailboxes.read'], 'public')
    check('confidential application registered with a secret', test_app['secret'] and test_app['secret'].startswith('fscs_'))
    check('public application registered without a secret', cli['secret'] is None)

    section('Metadata')
    meta = fetch('GET', '/.well-known/oauth-authorization-server').json() or {}
    check('RFC 8414 metadata', meta.get('token_endpoint') == BASE + '/oauth/token'
          and meta.get('code_challenge_methods_supported') == ['S256'], meta)

    section('Authorization request errors')
    alice_browser = Browser().login('alice@example.com')
    resp = alice_browser.get('/oauth/authorize?response_type=code&client_id=nope&redirect_uri=' + urllib.parse.quote(REDIRECT_URI))
    check('unknown client: error page, no redirect', resp.status == 400 and 'url=' not in resp.body)
    resp = alice_browser.get('/oauth/authorize?' + urllib.parse.urlencode({
        'response_type': 'code', 'client_id': test_app['client_id'], 'redirect_uri': 'https://evil.example/cb'}))
    check('unregistered redirect_uri: error page, no redirect', resp.status == 400 and 'evil.example' not in resp.body)
    result = authorize(alice_browser, test_app, ['bogus.scope'])
    check('unknown scope: invalid_scope sent back with state', result.get('error') == 'invalid_scope'
          and result.get('state') == result['_sent_state'], result)
    result = authorize(alice_browser, cli, ['conversations.read'], pkce=False)
    check('public client without PKCE: invalid_request', result.get('error') == 'invalid_request', result)
    result = authorize(alice_browser, cli, ['conversations.write'])
    check('scope the application may not ask for: invalid_scope', result.get('error') == 'invalid_scope', result)
    result = authorize(alice_browser, test_app, ['conversations.read'], extra={'prompt': 'none'})
    check('prompt=none before consent: consent_required', result.get('error') == 'consent_required', result)
    result = authorize(alice_browser, test_app, ['conversations.read'], decision='deny')
    check('user cancels: access_denied', result.get('_consent') and result.get('error') == 'access_denied', result)
    resp = fetch('GET', '/oauth/authorize?client_id=' + test_app['client_id'])
    check('not logged in: sent to the login page', resp.status == 302 and '/login' in resp.headers.get('Location', ''))
    fresh = Browser()
    verifier, challenge = pkce_pair()
    page = fresh.get('/oauth/authorize?' + urllib.parse.urlencode({
        'response_type': 'code', 'client_id': test_app['client_id'], 'redirect_uri': REDIRECT_URI,
        'scope': 'conversations.read', 'state': 's1', 'code_challenge': challenge, 'code_challenge_method': 'S256'}))
    page = fresh.post('/login', {'_token': csrf(page.body), 'email': 'carol@example.com', 'password': 'password123'})
    check('after logging in, back to the consent screen', 'name="decision"' in page.body and 'Test App' in page.body, page.url)

    section('Authorization code flow (Alice: mailbox A)')
    alice_scopes = ['conversations.read', 'conversations.write', 'customers.read', 'mailboxes.read', 'users.read', 'webhooks']
    result = authorize(alice_browser, test_app, alice_scopes)
    check('consent screen shown', result['_consent'])
    check('code returned with state and iss', result.get('code') and result.get('state') == result['_sent_state']
          and result.get('iss') == BASE, result)
    resp = exchange(test_app, result, verifier='x' * 50)
    check('wrong code_verifier: invalid_grant', resp.status == 400 and (resp.json() or {}).get('error') == 'invalid_grant', resp.body)
    resp = exchange(test_app, result, redirect_uri='http://127.0.0.1:5555/other')
    check('different redirect_uri: invalid_grant', resp.status == 400, resp.body)
    resp = exchange(test_app, result)
    first = resp.json() or {}
    check('code exchanged for tokens', resp.status == 200 and first.get('access_token', '').startswith('fsat_')
          and first.get('refresh_token', '').startswith('fsrt_') and first.get('token_type') == 'Bearer', resp.body)
    check('granted scope echoed', set(first.get('scope', '').split()) == set(alice_scopes), first.get('scope'))
    check('token response not cacheable', 'no-store' in (resp.headers.get('Cache-Control') or ''))
    resp = exchange(test_app, result)
    check('code replay: invalid_grant', resp.status == 400, resp.body)
    check('code replay revokes the tokens it produced', api(first['access_token'], 'GET', '/mailboxes').status == 401)
    bad = dict(test_app, secret='fscs_wrong')
    check('wrong client secret: invalid_client 401', token_request(bad, {'grant_type': 'authorization_code', 'code': 'x'}).status == 401)

    result = authorize(alice_browser, test_app, alice_scopes)
    check('already authorized: no consent screen the second time', not result['_consent'] and result.get('code'), result)
    alice = exchange(test_app, result).json()
    alice_token = alice['access_token']

    section('API as Alice')
    resp = api(alice_token, 'GET', '/mailboxes')
    check('mailboxes: only mailbox A', ids(resp, 'mailboxes') == [mailboxes['a']], resp.body)
    resp = api(alice_token, 'GET', '/conversations')
    check('conversations: only those in mailbox A', ids(resp, 'conversations') == sorted([conv_a1['id'], conv_a2['id']]), resp.body)
    check('conversation page count is exact', (resp.json() or {}).get('page', {}).get('totalElements') == 2, resp.body[-200:])
    resp = api(alice_token, 'GET', '/conversations?mailboxId=%d' % mailboxes['b'])
    check('conversations filtered to mailbox B: none', ids(resp, 'conversations') == [], resp.body)
    check('conversation in mailbox A: 200', api(alice_token, 'GET', '/conversations/%d' % conv_a1['id']).status == 200)
    check('conversation in mailbox B: 404', api(alice_token, 'GET', '/conversations/%d' % conv_b1['id']).status == 404)
    check('conversation id with junk ("%d-x"): 404' % conv_b1['id'], api(alice_token, 'GET', '/conversations/%d-x' % conv_b1['id']).status == 404)
    resp = api(alice_token, 'GET', '/users')
    check('users: only those sharing a mailbox', ids(resp, 'users') == sorted([users['alice'], users['carol'], users['dave']]), resp.body)
    check('users: page count is exact', (resp.json() or {}).get('page', {}).get('totalElements') == 3, resp.body[-200:])
    resp = api(alice_token, 'GET', '/users?email=bob@example.com')
    check('users: filtering by a hidden user\'s email reveals nothing', (resp.json() or {}).get('page', {}).get('totalElements') == 0, resp.body[-200:])
    check('user in another mailbox: 404', api(alice_token, 'GET', '/users/%d' % users['bob']).status == 404)
    check('user sharing a mailbox: 200', api(alice_token, 'GET', '/users/%d' % users['carol']).status == 200)
    resp = api(alice_token, 'GET', '/customers')
    check('customers: all (visibility not limited)', customer_c3 in ids(resp, 'customers'), resp.body)
    resp = api(alice_token, 'GET', '/tags')
    check('scope not granted (tags.read): 403 insufficient_scope', resp.status == 403
          and 'insufficient_scope' in (resp.headers.get('WWW-Authenticate') or ''), resp.status)
    check('scope not granted (users.write): 403', api(alice_token, 'POST', '/users', {'email': 'x@example.com', 'firstName': 'X', 'lastName': 'Y'}).status == 403)
    check('scope not granted (conversations.delete): 403', api(alice_token, 'DELETE', '/conversations/%d' % conv_a1['id']).status == 403)

    resp = api(alice_token, 'POST', '/conversations/%d/threads' % conv_a1['id'], {'type': 'note', 'text': 'Note by Alice', 'user': users['admin']})
    check('add note: 201', resp.status == 201, resp.body)
    threads = master_api('GET', '/conversations/%d?embed=threads' % conv_a1['id']).json()['_embedded']['threads']
    note = [t for t in threads if t.get('type') == 'note']
    check('note written as Alice, not as the user named in the request', note and note[0]['createdBy']['id'] == users['alice'], note[:1])
    check('add note to mailbox B conversation: 404',
          api(alice_token, 'POST', '/conversations/%d/threads' % conv_b1['id'], {'type': 'note', 'text': 'x', 'user': users['alice']}).status == 404)

    resp = api(alice_token, 'PUT', '/conversations/%d' % conv_a1['id'], {'status': 'pending', 'byUser': users['admin']})
    check('change status: 204', resp.status == 204, resp.body)
    check('status changed', master_api('GET', '/conversations/%d' % conv_a1['id']).json()['status'] == 'pending')
    check('move to a mailbox without access: 400',
          api(alice_token, 'PUT', '/conversations/%d' % conv_a1['id'], {'mailboxId': mailboxes['b']}).status == 400)
    check('assign to a user without access to the mailbox: 400',
          api(alice_token, 'PUT', '/conversations/%d' % conv_a1['id'], {'assignTo': users['bob']}).status == 400)
    check('assign to a user of the mailbox: 204',
          api(alice_token, 'PUT', '/conversations/%d' % conv_a1['id'], {'assignTo': users['carol']}).status == 204)
    check('assignee changed', (master_api('GET', '/conversations/%d' % conv_a1['id']).json()['assignee'] or {}).get('id') == users['carol'])
    check('rename subject: 204',
          api(alice_token, 'PUT', '/conversations/%d' % conv_a1['id'], {'subject': 'Renamed by Alice'}).status == 204)

    new_conv = {'type': 'email', 'subject': 'By Alice', 'imported': True, 'customer': {'email': 'c4@example.com'},
                'threads': [{'type': 'note', 'text': 'Started by Alice', 'user': users['admin']}]}
    check('create conversation in mailbox B: 400',
          api(alice_token, 'POST', '/conversations', dict(new_conv, mailboxId=mailboxes['b'])).status == 400)
    check('create conversation with mailbox_id variant in B: 400',
          api(alice_token, 'POST', '/conversations', dict(new_conv, mailboxId=mailboxes['a'], mailbox_id=mailboxes['b'])).status == 400)
    check('create conversation with MailboxId spelling in B (controller snake_cases keys): 400',
          api(alice_token, 'POST', '/conversations', dict(new_conv, mailboxId=mailboxes['a'], MailboxId=mailboxes['b'])).status == 400)
    resp = api(alice_token, 'POST', '/conversations', dict(new_conv, mailboxId=mailboxes['a']))
    check('create conversation in mailbox A: 201', resp.status == 201, resp.body)
    conv_alice = resp.json() or {}
    check('its thread is written as Alice', conv_alice.get('_embedded', {}).get('threads', [{}])[0].get('createdBy', {}).get('id') == users['alice'], resp.body[:300])
    spoof = dict(new_conv, mailboxId=mailboxes['a'], threads=[{'type': 'note', 'text': 'Spoof', 'User': users['admin']}])
    resp = api(alice_token, 'POST', '/conversations', spoof)
    check('thread author given as "User": still written as Alice', resp.status == 201
          and resp.json()['_embedded']['threads'][0]['createdBy']['id'] == users['alice'], resp.body[:300])
    resp = api(alice_token, 'POST', '/conversations/%d/threads' % conv_a1['id'], {'type': 'note', 'text': 'x', 'user': users['alice'], 'User': users['admin']})
    check('thread with both "user" and "User": 400', resp.status == 400, resp.body)

    check('token in X-FreeScout-API-Key header works', api(alice_token, 'GET', '/mailboxes', via='header').status == 200)
    check('token in api_key parameter works', api(alice_token, 'GET', '/mailboxes', via='query').status == 200)
    resp = fetch('GET', '/oauth/userinfo', headers={'Authorization': 'Bearer ' + alice_token})
    check('userinfo: Alice', (resp.json() or {}).get('id') == users['alice'] and resp.json().get('role') == 'user', resp.body)
    check('master key still works and sees everything', len(ids(master_api('GET', '/conversations'), 'conversations')) >= 4)

    section('Webhooks (Alice)')
    resp = api(alice_token, 'POST', '/webhooks', {'url': 'http://localhost:9000/alice', 'events': ['convo.created', 'convo.note.created']})
    check('create webhook: 201', resp.status == 201, resp.body)
    alice_hook = (resp.json() or {}).get('id')
    check('webhook for a mailbox without access: 400',
          api(alice_token, 'POST', '/webhooks', {'url': 'http://localhost:9000/x', 'events': ['convo.created'], 'mailboxes': [mailboxes['b']]}).status == 400)
    check('webhook with unknown event: 400',
          api(alice_token, 'POST', '/webhooks', {'url': 'http://localhost:9000/x', 'events': ['nope']}).status == 400)
    check('webhook to the cloud metadata address: 400',
          api(alice_token, 'POST', '/webhooks', {'url': 'http://169.254.169.254/latest/meta-data/', 'events': ['convo.created']}).status == 400)
    check('webhook to a private network address: 400',
          api(alice_token, 'POST', '/webhooks', {'url': 'http://10.1.2.3/hook', 'events': ['convo.created']}).status == 400)
    check('webhook with non-http url: 400',
          api(alice_token, 'POST', '/webhooks', {'url': 'file:///etc/passwd', 'events': ['convo.created']}).status == 400)
    resp = master_api('POST', '/webhooks', {'url': 'http://localhost:9000/admin', 'events': ['convo.created', 'convo.note.created']})
    admin_hook = (resp.json() or {}).get('id')
    check('admin webhook created with the master key', resp.status == 201, resp.body)
    resp = api(alice_token, 'GET', '/webhooks')
    check('list webhooks: only Alice\'s own', ids(resp, 'webhooks') == [alice_hook], resp.body)
    check('list webhooks: no delivery error text (could quote internal responses)', 'lastRunError' not in resp.body, resp.body)
    check('delete another application\'s webhook: 404', api(alice_token, 'DELETE', '/webhooks/%d' % admin_hook).status == 404)

    drain_queue()
    clear_webhook_log()
    in_b = create_conversation(mailboxes['b'], 'c5@example.com', 'Webhook test B')
    in_a = create_conversation(mailboxes['a'], 'c6@example.com', 'Webhook test A')
    master_api('POST', '/conversations/%d/threads' % conv_b1['id'], {'type': 'note', 'text': 'note in B', 'user': users['admin']})
    drain_queue()
    log = webhook_log()
    alice_got = sorted({(e['event'], e['body'].get('id')) for e in log if e['path'] == '/alice'})
    admin_got = sorted({(e['event'], e['body'].get('id')) for e in log if e['path'] == '/admin'})
    check('Alice\'s webhook: only the mailbox A event', alice_got == [('convo.created', in_a['id'])], alice_got)
    check('admin webhook: every event', ('convo.created', in_b['id']) in admin_got and ('convo.created', in_a['id']) in admin_got
          and ('convo.note.created', conv_b1['id']) in admin_got, admin_got)

    section('Only-assigned restriction (Carol)')
    carol_browser = Browser().login('carol@example.com')
    carol = connect(carol_browser, test_app, ['conversations.read'])
    resp = api(carol['access_token'], 'GET', '/conversations')
    visible = ids(resp, 'conversations')
    check('Carol lists only conversations assigned to her', conv_a2['id'] in visible and conv_alice.get('id') not in visible
          and conv_b1['id'] not in visible, visible)
    check('Carol: page count matches what she can see', (resp.json() or {}).get('page', {}).get('totalElements') == len(visible), resp.body[-200:])
    resp = api(carol['access_token'], 'GET', '/conversations?customerEmail=c6@example.com')
    check('Carol: filtering on a conversation she cannot see counts nothing', (resp.json() or {}).get('page', {}).get('totalElements') == 0, resp.body[-200:])
    check('Carol: unassigned conversation in her mailbox is 404',
          api(carol['access_token'], 'GET', '/conversations/%d' % in_a['id']).status == 404)

    section('Permissions within a scope')
    result = authorize(alice_browser, test_app, ['conversations.delete'])
    check('asking for a new scope shows the consent screen again', result['_consent'])
    alice_delete = exchange(test_app, result).json()
    resp = api(alice_delete['access_token'], 'DELETE', '/conversations/%d' % conv_alice['id'])
    check('Alice has the scope but not the permission to delete: 403', resp.status == 403 and 'permission' in resp.body, resp.body)
    dave_browser = Browser().login('dave@example.com')
    dave = connect(dave_browser, test_app, ['conversations.read', 'conversations.delete', 'users.read', 'users.write'])
    check('Dave (may delete) deletes a conversation: 204',
          api(dave['access_token'], 'DELETE', '/conversations/%d' % conv_alice['id']).status == 204)
    check('Dave cannot delete in a mailbox he cannot see: 404',
          api(dave['access_token'], 'DELETE', '/conversations/%d' % in_b['id']).status == 404)
    resp = api(dave['access_token'], 'POST', '/users', {
        'email': 'eve@example.com', 'firstName': 'Eve', 'lastName': 'Test', 'password': 'password123',
        'permissions': {'1': True, '10': True}})
    check('Dave (may manage users, not admin) cannot create users: 403', resp.status == 403, resp.body)
    check('Dave cannot delete users (admins only): 403',
          api(dave['access_token'], 'DELETE', '/users/%d' % users['carol']).status == 403)

    section('Administrator, public client with PKCE')
    result = authorize(admin, cli, ['conversations.read'])
    resp = token_request(cli, {'grant_type': 'authorization_code', 'code': result['code'], 'redirect_uri': REDIRECT_URI})
    check('public client without code_verifier: invalid_grant', resp.status == 400, resp.body)
    result = authorize(admin, cli, ['conversations.read'])
    admin_cli = exchange(cli, result).json()
    check('admin sees conversations of every mailbox',
          {conv_a2['id'], conv_b1['id']} <= set(ids(api(admin_cli['access_token'], 'GET', '/conversations'), 'conversations')))
    check('public client: consent screen every time, even when already authorized',
          authorize(admin, cli, ['conversations.read'])['_consent'])
    check('loopback redirect on another port is accepted',
          authorize(admin, cli, ['conversations.read'], redirect_uri='http://127.0.0.1:61234/callback').get('code'))
    check('mailboxes.read not granted to this token: 403', api(admin_cli['access_token'], 'GET', '/mailboxes').status == 403)
    admin_users = connect(admin, test_app, ['users.write'])['access_token']
    resp = api(admin_users, 'POST', '/users', {'email': 'eve@example.com', 'firstName': 'Eve', 'lastName': 'Test'})
    check('administrator creates a user: 201', resp.status == 201, resp.body[:200])

    section('Refresh tokens')
    resp = token_request(test_app, {'grant_type': 'refresh_token', 'refresh_token': alice['refresh_token'], 'scope': 'conversations.read'})
    refreshed = resp.json() or {}
    check('refresh with a narrower scope', resp.status == 200 and refreshed.get('scope') == 'conversations.read', resp.body)
    check('narrower token cannot use the dropped scope', api(refreshed['access_token'], 'GET', '/mailboxes').status == 403)
    resp = token_request(test_app, {'grant_type': 'refresh_token', 'refresh_token': alice['refresh_token']})
    check('reused refresh token: invalid_grant', resp.status == 400, resp.body)
    check('reuse revokes every token of the authorization', api(refreshed['access_token'], 'GET', '/conversations').status == 401
          and api(alice_token, 'GET', '/conversations').status == 401)
    resp = token_request(cli, {'grant_type': 'refresh_token', 'refresh_token': admin_cli['refresh_token'], 'scope': 'conversations.write'})
    check('refresh asking for a wider scope: invalid_scope', (resp.json() or {}).get('error') == 'invalid_scope', resp.body)
    resp = token_request(test_app, {'grant_type': 'refresh_token', 'refresh_token': admin_cli['refresh_token']})
    check('refresh token of another client: invalid_grant', resp.status == 400, resp.body)
    resp = token_request(cli, {'grant_type': 'refresh_token', 'refresh_token': admin_cli['refresh_token']})
    check('refresh after a rejected wider-scope request still works', resp.status == 200, resp.body)
    admin_cli = resp.json()

    section('Revocation')
    resp = fetch('POST', '/oauth/revoke', urllib.parse.urlencode({'token': admin_cli['access_token'], 'client_id': cli['client_id']}).encode(),
                {'Content-Type': 'application/x-www-form-urlencoded'})
    check('revocation endpoint: 200', resp.status == 200, resp.body)
    check('revoked token: 401', api(admin_cli['access_token'], 'GET', '/conversations').status == 401)

    alice = connect(alice_browser, test_app, alice_scopes)
    resp = api(alice['access_token'], 'POST', '/webhooks', {'url': 'http://localhost:9000/alice2', 'events': ['convo.created']})
    hook2 = (resp.json() or {}).get('id')
    page = alice_browser.get('/users/authorized-apps/%d' % users['alice'])
    check('Authorized Apps page lists the application', page.status == 200 and 'Test App' in page.body)
    check('the profile menu links to it', '/users/authorized-apps/%d' % users['alice'] in alice_browser.get('/users/profile/%d' % users['alice']).body)
    bob_browser = Browser().login('bob@example.com')
    check('another user cannot see Alice\'s apps: 403', bob_browser.get('/users/authorized-apps/%d' % users['alice']).status == 403)
    auth_id = re.search(r'name="authorization_id" value="(\d+)"', page.body).group(1)
    drain_queue()
    clear_webhook_log()
    queued = create_conversation(mailboxes['a'], 'c7@example.com', 'Queued before revoke')
    alice_browser.post('/users/authorized-apps/%d' % users['alice'], {'_token': csrf(page.body), 'authorization_id': auth_id})
    check('user revokes the app: its token stops working', api(alice['access_token'], 'GET', '/conversations').status == 401)
    left = php('return [\\Webhook::whereIn("id", [%d, %d])->count(), \\Modules\\OAuthApi\\Entities\\OAuthWebhook::where("user_id", %d)->count()];' % (alice_hook, hook2, users['alice']))
    check('...and its webhooks are deleted', left == [0, 0], left)
    drain_queue()
    check('...and an event queued before revoking is not delivered', not [e for e in webhook_log() if e['path'] == '/alice2'], webhook_log())

    section('Application disabled by the administrator')
    dave_token = dave['access_token']
    check('Dave\'s token works', api(dave_token, 'GET', '/conversations').status == 200)
    dave_hooks = connect(dave_browser, test_app, ['webhooks'])['access_token']
    dave_hook = api(dave_hooks, 'POST', '/webhooks', {'url': 'http://localhost:9000/dave', 'events': ['convo.created']}).json()['id']
    page = admin.get('/app-settings/oauthapi')
    test_app_row = php("return \\Modules\\OAuthApi\\Entities\\Client::where('client_id', '%s')->value('id');" % test_app['client_id'])
    fields = [('_token', csrf(page.body)), ('action', 'update'), ('id', str(test_app_row)), ('name', 'Test App'),
              ('redirect_uris', REDIRECT_URI)] + [('scopes[]', s) for s in ALL_SCOPES]
    admin.post('/oauth-api/clients', fields)
    check('disabled application: token 401', api(dave_token, 'GET', '/conversations').status == 401)
    check('disabled application: its webhooks are deleted', php('return \\Webhook::where("id", %d)->count();' % dave_hook) == 0)
    admin.post('/oauth-api/clients', fields + [('active', '1')])
    check('re-enabled: token works again', api(dave_token, 'GET', '/conversations').status == 200)
    fields_no_delete = [f for f in fields if f != ('scopes[]', 'conversations.delete')] + [('active', '1')]
    admin.post('/oauth-api/clients', fields_no_delete)
    check('scope taken from the application: 403 at once',
          api(dave_token, 'DELETE', '/conversations/%d' % in_a['id']).status == 403)

    native_keys = php("return class_exists('\\Modules\\ApiWebhooks\\Entities\\ApiKey');")
    if native_keys:
        section('API & Webhooks 1.0.11x: API access permission, new endpoints')
        page = bob_browser.get('/oauth/authorize?' + urllib.parse.urlencode({
            'response_type': 'code', 'client_id': test_app['client_id'], 'redirect_uri': REDIRECT_URI, 'scope': 'conversations.read'}))
        check('user without "access API" permission cannot authorize apps', page.status == 400 and 'not allowed to use the API' in page.body, page.status)
        php("$u = \\App\\User::find(%d); $p = $u->permissions; $p['api.access'] = false; $u->permissions = $p; $u->save(); return true;" % users['dave'])
        resp = api(dave_token, 'GET', '/conversations')
        check('permission taken away: token gets 403', resp.status == 403 and 'API access' in resp.body, resp.body[:200])
        php("$u = \\App\\User::find(%d); $p = $u->permissions; $p['api.access'] = true; $u->permissions = $p; $u->save(); return true;" % users['dave'])
        check('permission given back: token works', api(dave_token, 'GET', '/conversations').status == 200)

        resp = api(dave_token, 'GET', '/users/me')
        check('GET /users/me: the token\'s user, no scope needed', resp.status == 200 and (resp.json() or {}).get('id') == users['dave'], resp.body[:200])
        check('global time logs filtered to a conversation in another mailbox: 404',
              api(dave_token, 'GET', '/timelogs?conversationId=%d' % conv_b1['id']).status == 404)
        check('global time logs of another user (not admin): 403',
              api(dave_token, 'GET', '/timelogs?userId=%d' % users['alice']).status == 403)
        dave_write = connect(dave_browser, test_app, ['conversations.read', 'conversations.write'])['access_token']
        check('time log on a conversation in another mailbox: 404',
              api(dave_write, 'POST', '/conversations/%d/timelogs' % conv_b1['id'], {'duration': 60}).status == 404)
        check('time log for another user (not admin): 403',
              api(dave_write, 'POST', '/conversations/%d/timelogs' % conv_a2['id'], {'duration': 60, 'userId': users['alice']}).status == 403)
        dave_reports = connect(dave_browser, test_app, ['reports.read'])['access_token']
        check('reports, not admin: 403', api(dave_reports, 'GET', '/reports/conversations').status == 403)
        resp = api(dave_write, 'POST', '/conversations/%d/threads' % conv_a2['id'],
                   {'type': 'note', 'text': 'Native layer', 'user': users['admin']})
        check('note through both layers is still written as the token\'s user', resp.status == 201, resp.body[:200])

    section('Limited customer visibility (list filter fallback)')
    set_env('APP_LIMIT_USER_CUSTOMER_VISIBILITY', 'true')
    try:
        dave_customers_token = connect(dave_browser, test_app, ['customers.read', 'customers.write'])['access_token']
        dave_customers = ids(api(dave_customers_token, 'GET', '/customers'), 'customers')
        check('customers of other mailboxes are hidden', customer_c3 not in dave_customers and conv_a2['customer']['id'] in dave_customers, dave_customers)
        check('customer of another mailbox: 404', api(dave_customers_token, 'GET', '/customers/%d' % customer_c3).status == 404)
        check('updating a customer of another mailbox: 404',
              api(dave_customers_token, 'PUT', '/customers/%d' % customer_c3, {'firstName': 'Hacked'}).status == 404)
        dave_writes = connect(dave_browser, test_app, ['conversations.read', 'conversations.write', 'customers.read'])['access_token']
        visible_customer = conv_a2['customer']['id']
        resp = api(dave_writes, 'POST', '/conversations/%d/threads' % conv_a2['id'],
                   {'type': 'note', 'text': 'x', 'customer': {'0': {'id': visible_customer}, 'id': customer_c3}})
        check('hidden customer behind a visible decoy in customer[0]: 400', resp.status == 400, resp.body[:200])
        resp = api(dave_writes, 'POST', '/conversations', {
            'type': 'email', 'mailboxId': mailboxes['a'], 'subject': 'x', 'imported': True,
            'customer': {'0': {}, 'id': customer_c3}, 'threads': [{'type': 'note', 'text': 'x'}]})
        check('createConversation with customer {"0": {}, "id": hidden}: 400', resp.status == 400, resp.body[:200])
        resp = api(dave_writes, 'PUT', '/conversations/%d' % conv_a2['id'], {'customerId': '\u0000%d' % customer_c3})
        check('customerId with a leading NUL byte: 400', resp.status == 400, resp.body[:200])
        resp = api(dave_writes, 'POST', '/conversations/%d/threads' % conv_a2['id'],
                   {'type': 'note', 'text': 'x', 'customer': {'id': ' %d' % customer_c3}})
        check('customer id with whitespace: 400', resp.status == 400, resp.body[:200])
        check('hidden customer still hidden after all that', api(dave_customers_token, 'GET', '/customers/%d' % customer_c3).status == 404)
        dave_tags = connect(dave_browser, test_app, ['tags.read'])['access_token']
        check('tags of a conversation in another mailbox: 404',
              api(dave_tags, 'GET', '/tags?conversationId=%d' % conv_b1['id']).status == 404)
        admin_api = connect(admin, test_app, ['customers.read'])
        check('administrators still see every customer', customer_c3 in ids(api(admin_api['access_token'], 'GET', '/customers'), 'customers'))
    finally:
        unset_env('APP_LIMIT_USER_CUSTOMER_VISIBILITY')

    section('Kill switch')
    set_env('OAUTHAPI_DISABLED', 'true')
    try:
        check('OAUTHAPI_DISABLED: OAuth tokens 401', api(dave_token, 'GET', '/conversations').status == 401)
        check('OAUTHAPI_DISABLED: master key still works', master_api('GET', '/mailboxes').status == 200)
    finally:
        unset_env('OAUTHAPI_DISABLED')
    check('switched back on: token works', api(dave_token, 'GET', '/conversations').status == 200)

    print('\n%d passed, %d failed' % (passes, len(failures)))
    if failures:
        print('Failed:\n  ' + '\n  '.join(failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
