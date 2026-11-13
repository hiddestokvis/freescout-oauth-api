<?php
/**
 * Test helper, run inside the app container:
 *
 *   php /tests/php_eval.php 'return \App\User::count();'
 *
 * Boots FreeScout, runs the given PHP and prints the result as JSON.
 * Special command "drain": runs every due job on the "default" queue
 * (where webhook deliveries go).
 */
chdir('/var/www/html');
require 'vendor/autoload.php';
$app = require 'bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$code = $argv[1] ?? '';

if ($code === 'drain') {
    $ran = 0;
    for ($i = 0; $i < 100; $i++) {
        $due = \DB::table('jobs')->where('queue', 'default')->where('available_at', '<=', time())->count();
        if (!$due) {
            break;
        }
        \Artisan::call('queue:work', ['--once' => true, '--queue' => 'default', '--sleep' => 0, '--tries' => 1]);
        $ran++;
    }
    echo json_encode(['ran' => $ran]);
    exit;
}

$result = eval($code);
echo json_encode($result);
