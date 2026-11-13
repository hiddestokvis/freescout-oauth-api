<?php

namespace Modules\OAuthApi\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Modules\OAuthApi\Entities\AuthCode;
use Modules\OAuthApi\Entities\Client;
use Modules\OAuthApi\Entities\Token;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\WebhookManager;

/**
 * Registering applications: the forms on Manage » Settings » OAuth Apps.
 * Administrators only (enforced by the route).
 */
class ClientsController extends Controller
{
    public function handle(Request $request)
    {
        switch ($request->input('action')) {
            case 'create':
                $this->create($request);
                break;
            case 'update':
                $this->update($request);
                break;
            case 'regenerate_secret':
                $this->regenerateSecret($request);
                break;
            case 'revoke_all':
                $this->revokeAll($request);
                break;
            case 'delete':
                $this->delete($request);
                break;
        }

        return redirect()->route('settings', ['section' => OAUTHAPI_MODULE]);
    }

    protected function create(Request $request)
    {
        $client = new Client();
        $client->client_id = Client::generateClientId();
        $client->confidential = $request->input('type') !== 'public';
        $client->active = true;
        $client->created_by = auth()->id();

        if (!$this->fill($client, $request)) {
            return;
        }

        $secret = $client->confidential ? $client->regenerateSecret() : null;
        $client->save();

        \Session::flash('oauthapi_new_client', [
            'id'        => $client->id,
            'name'      => $client->name,
            'client_id' => $client->client_id,
            'secret'    => $secret,
        ]);
        $this->success(__('Application registered'));
    }

    protected function update(Request $request)
    {
        $client = $this->find($request);
        if (!$client || !$this->fill($client, $request)) {
            return;
        }

        $client->active = (bool) $request->input('active');
        $client->save();

        // Webhooks go with access; the application recreates them once
        // it is enabled again.
        if (!$client->active || !in_array(Scopes::WEBHOOKS, $client->allowedScopes())) {
            foreach ($client->authorizations as $authorization) {
                WebhookManager::deleteForAuthorization($authorization);
            }
        }

        $this->success(__('Application updated'));
    }

    protected function regenerateSecret(Request $request)
    {
        $client = $this->find($request);
        if (!$client || !$this->confirmed($client, $request)) {
            return;
        }
        if (!$client->confidential) {
            $this->error(__('Public applications have no secret.'));

            return;
        }

        $secret = $client->regenerateSecret();
        $client->save();

        \Session::flash('oauthapi_new_client', [
            'id'        => $client->id,
            'name'      => $client->name,
            'client_id' => $client->client_id,
            'secret'    => $secret,
        ]);
        $this->success(__('New client secret created. The old one no longer works.'));
    }

    protected function revokeAll(Request $request)
    {
        $client = $this->find($request);
        if (!$client || !$this->confirmed($client, $request)) {
            return;
        }

        $client->revokeAll();

        $this->success(__('All authorizations of this application were revoked'));
    }

    protected function delete(Request $request)
    {
        $client = $this->find($request);
        if (!$client || !$this->confirmed($client, $request)) {
            return;
        }

        $client->revokeAll();

        $authorization_ids = $client->authorizations()->pluck('id')->all();
        Token::whereIn('authorization_id', $authorization_ids)->delete();
        AuthCode::whereIn('authorization_id', $authorization_ids)->delete();
        $client->authorizations()->delete();
        $client->delete();

        $this->success(__('Application deleted'));
    }

    /**
     * Name, redirect URIs and scopes from the form. Returns false (with
     * an error shown) when something is wrong.
     */
    protected function fill(Client $client, Request $request)
    {
        $name = trim((string) $request->input('name'));
        if ($name === '' || mb_strlen($name) > 100) {
            $this->error(__('Give the application a name of at most 100 characters.'));

            return false;
        }

        $uris = array_values(array_unique(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', (string) $request->input('redirect_uris'))), 'strlen')));
        if (!$uris) {
            $this->error(__('Add at least one redirect URI.'));

            return false;
        }
        foreach ($uris as $uri) {
            if ($error = Client::redirectUriError($uri)) {
                $this->error($error);

                return false;
            }
        }

        $scopes = Scopes::valid($request->input('scopes'));
        if (!$scopes) {
            $this->error(__('Choose at least one scope.'));

            return false;
        }

        $client->name = $name;
        $client->redirect_uris = $uris;
        $client->scopes = $scopes;

        return true;
    }

    protected function find(Request $request)
    {
        $client = Client::find((int) $request->input('id'));
        if (!$client) {
            $this->error(__('Application not found'));
        }

        return $client;
    }

    /**
     * Destructive actions need the application name typed in.
     */
    protected function confirmed(Client $client, Request $request)
    {
        if (trim((string) $request->input('confirm')) !== $client->name) {
            $this->error(__('Type the application name in the Confirm field first.'));

            return false;
        }

        return true;
    }

    protected function success($message)
    {
        \Session::flash('flash_success_floating', $message);
    }

    protected function error($message)
    {
        \Session::flash('flash_error_floating', $message);
    }
}
