@extends('layouts.app')

@section('title', __('Authorize :app', ['app' => $client->name]))

@section('content')
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default panel-shaded margin-top">
                <div class="panel-body">
                    <h3 class="margin-top-0">{{ __(':app wants to access your FreeScout account', ['app' => $client->name]) }}</h3>

                    <p class="text-help">
                        {{ __('You are logged in as :name (:email).', ['name' => $user->getFullName(), 'email' => $user->email]) }}
                    </p>

                    <p>{{ __('If you allow it, :app will be able to:', ['app' => $client->name]) }}</p>

                    <ul>
                        @foreach ($scopes as $scope)
                            <li>
                                {{ \Modules\OAuthApi\Support\Scopes::description($scope) }}
                                @if (in_array($scope, \Modules\OAuthApi\Support\Scopes::$sensitive))
                                    <span class="label label-danger">{{ __('Sensitive') }}</span>
                                @endif
                                @if (in_array($scope, $previous))
                                    <span class="text-help">({{ __('already allowed') }})</span>
                                @endif
                            </li>
                        @endforeach
                    </ul>

                    <p class="text-help">
                        {{ __('It acts as you: it can only reach the mailboxes, conversations and customers you can reach in FreeScout. You can revoke its access at any time under your profile, in Authorized Apps.') }}
                    </p>

                    <form method="POST" action="{{ route('oauthapi.authorize.decide') }}" class="margin-top">
                        {{ csrf_field() }}
                        @foreach ($params->formFields() as $name => $value)
                            <input type="hidden" name="{{ $name }}" value="{{ $value }}" />
                        @endforeach

                        <button type="submit" class="btn btn-primary" name="decision" value="approve">{{ __('Allow') }}</button>
                        <button type="submit" class="btn btn-default" name="decision" value="deny">{{ __('Cancel') }}</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
