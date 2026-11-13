@php
    $new_client = session('oauthapi_new_client');
    $migrations_pending = $migrations_pending ?? false;
@endphp

@if ($migrations_pending)
    <div class="alert alert-warning margin-top" role="alert">
        <strong>{{ __('One more step:') }}</strong>
        {{ __('the module\'s database tables have not been created yet. Go to Manage » System and press "Migrate DB", or run "php artisan migrate --force", then reload this page.') }}
    </div>
@else

@if (!$apiwebhooks_active)
    <div class="alert alert-warning margin-top" role="alert">
        {{ __('The API & Webhooks module is not active. OAuth access tokens can only be used when it is.') }}
    </div>
@endif

{{-- Credentials of a newly registered application, shown this once. --}}
@if ($new_client)
    <div class="alert alert-warning margin-top" role="alert">
        <p><strong>{{ __('Credentials for') }} “{{ $new_client['name'] }}”.</strong>
            @if ($new_client['secret']) {{ __('Copy the client secret now: it is only shown this once.') }} @endif</p>
        <div class="form-horizontal">
            <div class="form-group margin-bottom-0">
                <label class="col-sm-2 control-label" for="oauthapi-new-client-id">{{ __('Client ID') }}</label>
                <div class="col-sm-8">
                    <input type="text" id="oauthapi-new-client-id" class="form-control input-sized-lg" readonly value="{{ $new_client['client_id'] }}" />
                </div>
            </div>
            @if ($new_client['secret'])
                <div class="form-group margin-bottom-0 margin-top-10">
                    <label class="col-sm-2 control-label" for="oauthapi-new-client-secret">{{ __('Client Secret') }}</label>
                    <div class="col-sm-8">
                        <input type="text" id="oauthapi-new-client-secret" class="form-control input-sized-lg" readonly value="{{ $new_client['secret'] }}" />
                    </div>
                </div>
            @endif
        </div>
        <div class="clearfix"></div>
    </div>
@endif

{{-- How applications connect. --}}
<h3 class="subheader">{{ __('Endpoints') }}</h3>

<p class="col-sm-10 text-help">
    {{ __('Applications send users to the authorization URL, where they log in to FreeScout and approve access. The application then gets an access token that works on the regular API (https://api-docs.freescout.net) in the "Authorization: Bearer" header. It acts as that user: it can only see and do what the user can in FreeScout, limited further by the scopes approved.') }}
</p>
<div class="clearfix"></div>

<div class="form-horizontal">
    @foreach ([
        __('Authorization URL') => route('oauthapi.authorize'),
        __('Token URL') => route('oauthapi.token'),
        __('Revocation URL') => route('oauthapi.revoke'),
        __('User info URL') => route('oauthapi.userinfo'),
        __('Server metadata') => route('oauthapi.metadata'),
        __('API base URL') => rtrim(config('app.url'), '/').'/api/',
    ] as $label => $url)
        <div class="form-group margin-bottom-0">
            <label class="col-sm-2 control-label">{{ $label }}</label>
            <div class="col-sm-8">
                <input type="text" class="form-control input-sized-lg" readonly value="{{ $url }}" />
            </div>
        </div>
    @endforeach
</div>

{{-- Token lifetimes: the module's stored settings. --}}
<form class="form-horizontal margin-top" method="POST" action="">
    {{ csrf_field() }}

    <h3 class="subheader">{{ __('Token Lifetimes') }}</h3>

    <div class="form-group">
        <label for="oauthapi-access-ttl" class="col-sm-2 control-label">{{ __('Access tokens') }}</label>
        <div class="col-sm-6">
            <div class="input-group input-sized">
                <input id="oauthapi-access-ttl" type="number" min="5" max="1440" class="form-control" name="settings[oauthapi.access_token_ttl]" value="{{ $settings['oauthapi.access_token_ttl'] }}" />
                <span class="input-group-addon">{{ __('minutes') }}</span>
            </div>
            <p class="form-help">{{ __('5 to 1440. Applications get a new access token with their refresh token when it runs out.') }}</p>
        </div>
    </div>

    <div class="form-group">
        <label for="oauthapi-refresh-ttl" class="col-sm-2 control-label">{{ __('Refresh tokens') }}</label>
        <div class="col-sm-6">
            <div class="input-group input-sized">
                <input id="oauthapi-refresh-ttl" type="number" min="1" max="365" class="form-control" name="settings[oauthapi.refresh_token_ttl]" value="{{ $settings['oauthapi.refresh_token_ttl'] }}" />
                <span class="input-group-addon">{{ __('days') }}</span>
            </div>
            <p class="form-help">{{ __('1 to 365. Every refresh gives a new refresh token; an application unused for longer than this must be authorized again.') }}</p>
        </div>
    </div>

    <div class="form-group margin-top-0 margin-bottom-0">
        <div class="col-sm-6 col-sm-offset-2">
            <button type="submit" class="btn btn-primary">{{ __('Save') }}</button>
        </div>
    </div>
</form>

{{-- Register an application. --}}
<form class="form-horizontal margin-top" method="POST" action="{{ route('oauthapi.clients') }}">
    {{ csrf_field() }}

    <h3 class="subheader">{{ __('Register an Application') }}</h3>

    @include('oauthapi::partials/client_fields', ['client' => null, 'suffix' => 'new'])

    <div class="form-group">
        <label class="col-sm-2 control-label">{{ __('Type') }}</label>
        <div class="col-sm-8">
            <div class="radio">
                <label><input type="radio" name="type" value="confidential" checked /> <strong>{{ __('Confidential') }}</strong> — {{ __('a server-side application that can keep a client secret.') }}</label>
            </div>
            <div class="radio">
                <label><input type="radio" name="type" value="public" /> <strong>{{ __('Public') }}</strong> — {{ __('a browser, desktop, mobile or command line application. No secret; PKCE is required.') }}</label>
            </div>
        </div>
    </div>

    <div class="form-group margin-top margin-bottom">
        <div class="col-sm-6 col-sm-offset-2">
            <button type="submit" class="btn btn-primary" name="action" value="create">{{ __('Register Application') }}</button>
        </div>
    </div>
</form>

{{-- Registered applications. --}}
@if (count($clients))
    <h3 class="subheader">{{ __('Applications') }}</h3>

    @foreach ($clients as $client)
        <div class="col-lg-9" id="oauthapi-client-{{ $client->id }}">
            <form class="form-horizontal margin-top panel panel-shaded panel-padded" method="POST" action="{{ route('oauthapi.clients') }}">
                {{ csrf_field() }}
                <input type="hidden" name="id" value="{{ $client->id }}" />

                <h4>
                    {{ $client->name }}
                    @if (!$client->active)
                        <span class="label label-default">{{ __('Disabled') }}</span>
                    @endif
                    <small>{{ $client->confidential ? __('Confidential') : __('Public') }}</small>
                </h4>

                <div class="form-group">
                    <label class="col-sm-2 control-label">{{ __('Client ID') }}</label>
                    <div class="col-sm-8">
                        <input type="text" class="form-control input-sized-lg" readonly value="{{ $client->client_id }}" />
                        <p class="form-help">
                            {{ __('Connected users') }}: {{ $client->activeAuthorizationsCount() }}.
                            {{ __('Registered') }} {{ App\User::dateFormat($client->created_at) }}.
                        </p>
                    </div>
                </div>

                @include('oauthapi::partials/client_fields', ['client' => $client, 'suffix' => $client->id])

                <div class="form-group">
                    <div class="col-sm-8 col-sm-offset-2">
                        <div class="checkbox">
                            <label><input type="checkbox" name="active" value="1" @if ($client->active) checked @endif /> {{ __('Enabled') }}</label>
                        </div>
                        <p class="form-help">{{ __('While disabled, the application\'s tokens do not work and nobody can authorize it. Disabling it, or taking away its webhooks scope, deletes its webhooks.') }}</p>
                    </div>
                </div>

                <div class="form-group">
                    <div class="col-sm-8 col-sm-offset-2">
                        <button type="submit" class="btn btn-primary" name="action" value="update">{{ __('Save') }}</button>
                    </div>
                </div>

                <hr/>

                <div class="form-group">
                    <label for="oauthapi-confirm-{{ $client->id }}" class="col-sm-2 control-label">{{ __('Confirm') }}</label>
                    <div class="col-sm-6">
                        <input id="oauthapi-confirm-{{ $client->id }}" type="text" name="confirm" class="form-control input-sized" autocomplete="off" />
                        <p class="form-help">{{ __('Type the application name here before using the buttons below.') }}</p>
                    </div>
                </div>

                <div class="form-group margin-bottom-0">
                    <div class="col-sm-8 col-sm-offset-2">
                        @if ($client->confidential)
                            <button type="submit" class="btn btn-default" name="action" value="regenerate_secret">{{ __('New Client Secret') }}</button>
                        @endif
                        <button type="submit" class="btn btn-default" name="action" value="revoke_all">{{ __('Disconnect All Users') }}</button>
                        <button type="submit" class="btn btn-default text-danger" name="action" value="delete">{{ __('Delete') }}</button>
                    </div>
                </div>
            </form>
        </div>
        <div class="clearfix"></div>
    @endforeach
@endif

@endif
