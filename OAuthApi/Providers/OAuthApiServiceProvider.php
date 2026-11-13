<?php

namespace Modules\OAuthApi\Providers;

use Illuminate\Support\ServiceProvider;
use Modules\OAuthApi\Entities\Authorization;
use Modules\OAuthApi\Entities\Client;
use Modules\OAuthApi\Http\Middleware\AuthenticateOAuthToken;
use Modules\OAuthApi\Support\Access;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\Settings;
use Modules\OAuthApi\Support\WebhookManager;

// Module alias
define('OAUTHAPI_MODULE', 'oauthapi');

class OAuthApiServiceProvider extends ServiceProvider
{
    /**
     * Boot the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerConfig();
        $this->registerViews();
        $this->loadMigrationsFrom(__DIR__.'/../Database/Migrations');
        $this->registerMiddleware();
        $this->hooks();
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->commands([
            \Modules\OAuthApi\Console\Purge::class,
        ]);
    }

    protected function registerConfig()
    {
        $this->publishes([
            __DIR__.'/../Config/config.php' => config_path('oauthapi.php'),
        ], 'config');
        $this->mergeConfigFrom(
            __DIR__.'/../Config/config.php', 'oauthapi'
        );
    }

    public function registerViews()
    {
        $viewPath = resource_path('views/modules/oauthapi');

        $sourcePath = __DIR__.'/../Resources/views';

        $this->publishes([
            $sourcePath => $viewPath,
        ], 'views');

        $this->loadViewsFrom(array_merge(array_map(function ($path) {
            return $path.'/modules/oauthapi';
        }, \Config::get('view.paths')), [$sourcePath]), 'oauthapi');
    }

    /**
     * The token check must run before the API & Webhooks auth middleware,
     * which is attached to its routes. Global middleware always runs
     * first; it exits straight away on anything that is not an API request
     * with an OAuth token.
     */
    protected function registerMiddleware()
    {
        $this->app->make(\Illuminate\Contracts\Http\Kernel::class)
            ->prependMiddleware(AuthenticateOAuthToken::class);
    }

    /**
     * Module hooks.
     */
    public function hooks()
    {
        $this->settingsHooks();
        $this->profileHooks();
        $this->apiHooks();
        $this->webhookHooks();

        // Housekeeping: drop expired codes and tokens.
        \Eventy::addFilter('schedule', function ($schedule) {
            $schedule->command('oauthapi:purge')->dailyAt('03:17');

            return $schedule;
        });

        // A deleted user's applications lose access at once.
        \Eventy::addAction('user.deleted', function ($deleted_user, $by_user = null) {
            if (!$deleted_user || !\Schema::hasTable('oauthapi_authorizations')) {
                return;
            }
            foreach (Authorization::where('user_id', $deleted_user->id)->whereNull('revoked_at')->get() as $authorization) {
                $authorization->revoke();
            }
        }, 20, 2);
    }

    /**
     * Manage » Settings » OAuth Apps.
     */
    protected function settingsHooks()
    {
        \Eventy::addFilter('settings.sections', function ($sections) {
            $sections[OAUTHAPI_MODULE] = ['title' => __('OAuth Apps'), 'icon' => 'link', 'order' => 620];

            return $sections;
        }, 42);

        // The token lifetimes are the stored settings; applications live
        // in their own table and are saved by ClientsController.
        \Eventy::addFilter('settings.section_settings', function ($settings, $section) {
            if ($section != OAUTHAPI_MODULE) {
                return $settings;
            }

            $settings[Settings::ACCESS_TOKEN_TTL] = Settings::accessTokenTtlMinutes();
            $settings[Settings::REFRESH_TOKEN_TTL] = Settings::refreshTokenTtlDays();

            return $settings;
        }, 20, 2);

        \Eventy::addFilter('settings.section_params', function ($params, $section) {
            if ($section != OAUTHAPI_MODULE) {
                return $params;
            }

            // Activating a module does not run its migrations: that needs
            // Manage » System » Migrate DB (or php artisan migrate).
            $migrations_pending = !\Schema::hasTable('oauthapi_webhooks');

            return [
                'template_vars' => [
                    'migrations_pending' => $migrations_pending,
                    'apiwebhooks_active' => class_exists('\ApiWebhooks'),
                    'clients'            => $migrations_pending ? collect() : Client::orderBy('name')->get(),
                    'scope_catalogue'    => Scopes::catalogue(),
                    'sensitive_scopes'   => Scopes::$sensitive,
                ],
                'settings' => [
                    Settings::ACCESS_TOKEN_TTL  => ['default' => Settings::DEFAULT_ACCESS_TOKEN_TTL],
                    Settings::REFRESH_TOKEN_TTL => ['default' => Settings::DEFAULT_REFRESH_TOKEN_TTL],
                ],
            ];
        }, 20, 2);

        \Eventy::addFilter('settings.view', function ($view, $section) {
            if ($section != OAUTHAPI_MODULE) {
                return $view;
            }

            return 'oauthapi::settings';
        }, 20, 2);
    }

    /**
     * "Authorized Apps" in the user profile menu.
     */
    protected function profileHooks()
    {
        \Eventy::addAction('user.profile.menu.after_profile', function ($user) {
            $auth_user = auth()->user();
            if (!$user || !$auth_user || (!$auth_user->isAdmin() && $auth_user->id != $user->id)) {
                return;
            }

            $active = \Route::currentRouteName() == 'oauthapi.user_apps' ? ' class="active"' : '';

            echo '<li'.$active.'><a href="'.e(route('oauthapi.user_apps', ['id' => $user->id])).'">'
                .'<i class="glyphicon glyphicon-link"></i> '.e(__('Authorized Apps')).'</a></li>';
        });
    }

    /**
     * Hooks of the API & Webhooks module. The middleware already checked
     * the request; these narrow database queries so lists have exact page
     * counts, and add a second check where the hooks exist. Older
     * API & Webhooks versions do not have them, and ListFilter covers
     * lists there.
     */
    protected function apiHooks()
    {
        // The endpoint that runs must be the one the middleware checked.
        \Eventy::addFilter('api.auth.allowed', function ($allowed, $request) {
            if (!$allowed || !$request->attributes->has('oauthapi_method')) {
                return $allowed;
            }

            $route = $request->route();
            $method = $route ? $route->getActionMethod() : null;

            if ($method !== $request->attributes->get('oauthapi_method')) {
                \Log::error('[OAuthApi] Route mismatch: checked "'.$request->attributes->get('oauthapi_method').'", dispatching "'.$method.'". Request refused.');

                return false;
            }

            return $allowed;
        }, 20, 2);

        // Lists.
        \Eventy::addFilter('api.conversations.query', function ($query, $request) {
            $user = Access::userFor($request);

            return $user ? Access::scopeConversations($query, $user) : $query;
        }, 20, 2);

        \Eventy::addFilter('api.customers.query', function ($query, $request) {
            $user = Access::userFor($request);

            return $user ? Access::scopeCustomers($query, $user) : $query;
        }, 20, 2);

        \Eventy::addFilter('api.users.query', function ($query, $request) {
            $user = Access::userFor($request);

            return $user ? Access::scopeUsers($query, $user) : $query;
        }, 20, 2);

        \Eventy::addFilter('api.mailboxes.query', function ($query, $request) {
            $user = Access::userFor($request);

            return $user ? Access::scopeMailboxes($query, $user) : $query;
        }, 20, 2);

        // Single records: "not found" when the user cannot see them.
        \Eventy::addFilter('api.conversation.find', function ($conversation, $request) {
            $user = Access::userFor($request);

            return ($user && $conversation && !Access::canViewConversation($user, $conversation)) ? null : $conversation;
        }, 20, 2);

        \Eventy::addFilter('api.customer.find', function ($customer, $request) {
            $user = Access::userFor($request);

            return ($user && $customer && !Access::canViewCustomer($user, $customer)) ? null : $customer;
        }, 20, 2);

        \Eventy::addFilter('api.user.find', function ($found, $request) {
            $user = Access::userFor($request);

            return ($user && $found && !Access::canViewUser($user, $found)) ? null : $found;
        }, 20, 2);

        \Eventy::addFilter('api.mailbox.find', function ($mailbox, $request) {
            $user = Access::userFor($request);

            return ($user && $mailbox && !Access::canViewMailbox($user, $mailbox)) ? null : $mailbox;
        }, 20, 2);
    }

    /**
     * Before the API & Webhooks module delivers a webhook (priority 20),
     * check webhooks made through OAuth against their user's access.
     *
     * This keeps running when the module is switched off with
     * OAUTHAPI_DISABLED: it only ever holds deliveries back.
     */
    protected function webhookHooks()
    {
        \Eventy::addAction('webhook.run', function ($webhook, $event, $data) {
            static $installed = null;
            if ($installed === null) {
                $installed = \Schema::hasTable('oauthapi_webhooks');
            }
            if ($installed) {
                WebhookManager::guardDelivery($webhook, $event, $data);
            }
        }, 10, 3);
    }
}
