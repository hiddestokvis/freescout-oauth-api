@extends('layouts.app')

@section('title_full', __('Authorized Apps').' - '.$user->getFullName())

@section('sidebar')
    @include('partials/sidebar_menu_toggle')
    @include('users/sidebar_menu')
@endsection

@section('content')
    <div class="section-heading">
        {{ __('Authorized Apps') }}
    </div>

    @include('partials/flash_messages')

    <div class="container">
        <div class="row">
            <div class="col-xs-12">
                <p class="margin-top text-help">
                    {{ __('Applications connected to this account through OAuth. Each one acts as this user, within the scopes listed. Revoking stops its access at once and deletes its webhooks.') }}
                </p>

                @if (count($authorizations))
                    <table class="table table-striped margin-top">
                        <thead>
                            <tr>
                                <th>{{ __('Application') }}</th>
                                <th>{{ __('Access') }}</th>
                                <th>{{ __('Authorized') }}</th>
                                <th>{{ __('Last used') }}</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($authorizations as $authorization)
                                <tr>
                                    <td>
                                        {{ $authorization->client->name }}
                                        @if (!$authorization->client->active)
                                            <span class="label label-default">{{ __('Disabled') }}</span>
                                        @endif
                                    </td>
                                    <td>
                                        @foreach ($authorization->effectiveScopes() as $scope)
                                            <code title="{{ \Modules\OAuthApi\Support\Scopes::description($scope) }}">{{ $scope }}</code>
                                        @endforeach
                                    </td>
                                    <td>{{ App\User::dateFormat($authorization->created_at) }}</td>
                                    <td>{{ $authorization->last_used_at ? App\User::dateFormat($authorization->last_used_at) : '—' }}</td>
                                    <td class="text-right">
                                        <form method="POST" action="{{ route('oauthapi.user_apps.revoke', ['id' => $user->id]) }}">
                                            {{ csrf_field() }}
                                            <input type="hidden" name="authorization_id" value="{{ $authorization->id }}" />
                                            <button type="submit" class="btn btn-default btn-sm text-danger">{{ __('Revoke') }}</button>
                                        </form>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                @else
                    <p class="margin-top">{{ __('No applications are connected.') }}</p>
                @endif
            </div>
        </div>
    </div>
@endsection
