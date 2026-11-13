@php
    $client_scopes = $client ? $client->allowedScopes() : [];
@endphp

<div class="form-group">
    <label for="oauthapi-name-{{ $suffix }}" class="col-sm-2 control-label">{{ __('Name') }}</label>
    <div class="col-sm-6">
        <input id="oauthapi-name-{{ $suffix }}" type="text" name="name" maxlength="100" class="form-control input-sized-lg" value="{{ $client ? $client->name : '' }}" required />
        <p class="form-help">{{ __('Shown to users when they are asked to authorize the application.') }}</p>
    </div>
</div>

<div class="form-group">
    <label for="oauthapi-redirect-{{ $suffix }}" class="col-sm-2 control-label">{{ __('Redirect URIs') }}</label>
    <div class="col-sm-8">
        <textarea id="oauthapi-redirect-{{ $suffix }}" name="redirect_uris" rows="3" class="form-control input-sized-lg" required placeholder="https://app.example.com/oauth/callback">{{ $client ? implode("\n", $client->redirectUris()) : '' }}</textarea>
        <p class="form-help">{{ __('One per line, matched exactly. https, or http only for 127.0.0.1, [::1] and localhost (any port).') }}</p>
    </div>
</div>

<div class="form-group">
    <label class="col-sm-2 control-label">{{ __('Allowed scopes') }}</label>
    <div class="col-sm-8">
        @foreach ($scope_catalogue as $group => $scopes)
            <div class="margin-bottom-10">
                <strong>{{ $group }}</strong>
                @foreach ($scopes as $scope => $description)
                    <div class="checkbox margin-top-0 margin-bottom-0">
                        <label>
                            <input type="checkbox" name="scopes[]" value="{{ $scope }}" @if (in_array($scope, $client_scopes)) checked @endif />
                            <code>{{ $scope }}</code> {{ $description }}
                            @if (in_array($scope, $sensitive_scopes))
                                <span class="label label-danger">{{ __('Sensitive') }}</span>
                            @endif
                        </label>
                    </div>
                @endforeach
            </div>
        @endforeach
        <p class="form-help">{{ __('The most the application can ask for. Users approve the scopes it asks for, and the token never does more than the user can do in FreeScout.') }}</p>
    </div>
</div>
