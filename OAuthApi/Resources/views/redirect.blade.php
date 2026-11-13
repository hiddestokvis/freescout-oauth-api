<!DOCTYPE html>
<html lang="{{ app()->getLocale() }}">
<head>
    <meta charset="utf-8">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="refresh" content="0;url={{ $url }}">
    <title>{{ __('Returning to :app', ['app' => $client->name]) }}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; text-align: center; padding-top: 80px; color: #333;">
    <p>{{ __('Returning to :app…', ['app' => $client->name]) }}</p>
    <p><a href="{{ $url }}">{{ __('Continue') }}</a></p>
</body>
</html>
