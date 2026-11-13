<?php
/**
 * Test fixtures. Run inside the app container:
 *
 *   php /tests/seed.php
 *
 * Activates both modules and creates two mailboxes and four users with
 * different access. Prints IDs and the master API key as JSON.
 */
chdir('/var/www/html');
require 'vendor/autoload.php';
$app = require 'bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use App\Mailbox;
use App\User;

\App\Module::setActive('apiwebhooks', true);
\App\Module::setActive('oauthapi', true);

function seed_user($email, $first_name, $role, $permissions = [])
{
    $user = User::where('email', $email)->first() ?: new User();
    $user->email = $email;
    $user->first_name = $first_name;
    $user->last_name = 'Test';
    $user->role = $role;
    $user->password = \Hash::make('password123');
    $user->status = User::STATUS_ACTIVE;
    $user->invite_state = User::INVITE_STATE_ACTIVATED;
    $user->permissions = $permissions;
    $user->save();

    return $user;
}

function seed_mailbox($email, $name, array $users)
{
    $mailbox = Mailbox::where('email', $email)->first() ?: new Mailbox();
    $mailbox->email = $email;
    $mailbox->name = $name;
    $mailbox->save();
    $mailbox->users()->sync(array_map(function ($user) { return $user->id; }, $users));
    $mailbox->syncPersonalFolders(array_map(function ($user) { return $user->id; }, $users));

    return $mailbox;
}

$admin = seed_user('admin@example.com', 'Admin', User::ROLE_ADMIN);
// "Users are allowed to access API", API & Webhooks 1.0.11x and later.
$api = ['api.access' => true];

// Alice: mailbox A. May not delete conversations.
$alice = seed_user('alice@example.com', 'Alice', User::ROLE_USER, $api);
// Bob: mailbox B only, and no API access.
$bob = seed_user('bob@example.com', 'Bob', User::ROLE_USER);
// Carol: mailbox A, but sees only conversations assigned to her.
$carol = seed_user('carol@example.com', 'Carol', User::ROLE_USER, $api + [User::PERM_ONLY_ASSIGNED_TICKETS => true]);
// Dave: mailbox A, may delete conversations and manage users.
$dave = seed_user('dave@example.com', 'Dave', User::ROLE_USER, $api + [
    User::PERM_DELETE_CONVERSATIONS => true,
    User::PERM_EDIT_USERS           => true,
]);

$mailbox_a = seed_mailbox('support-a@example.com', 'Mailbox A', [$alice, $carol, $dave]);
$mailbox_b = seed_mailbox('support-b@example.com', 'Mailbox B', [$bob]);

// In a new process: this one booted before the modules were active, and
// would rebuild the caches without their routes.
exec('php artisan freescout:clear-cache');

echo json_encode([
    // As \ApiWebhooks::getApiKey(); the module is only loaded on the next request.
    'master_key' => md5(config('app.key').'api_key'.env('APIWEBHOOKS_API_KEY_SALT', '')),
    'users'      => [
        'admin' => $admin->id,
        'alice' => $alice->id,
        'bob'   => $bob->id,
        'carol' => $carol->id,
        'dave'  => $dave->id,
    ],
    'mailboxes'  => [
        'a' => $mailbox_a->id,
        'b' => $mailbox_b->id,
    ],
]);
