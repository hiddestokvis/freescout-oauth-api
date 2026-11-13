#!/bin/sh
# Installs FreeScout on first start, then the API & Webhooks module and
# the OAuth API module (both mounted under /modules-src), and starts a
# small webhook receiver on port 9000 that appends what it gets to
# /tmp/webhooks.log.
set -e
cd /var/www/html

if [ ! -f .env ]; then
    cat > .env <<EOF
APP_URL=http://localhost:${HOST_PORT:-8088}
APP_KEY=base64:$(head -c 32 /dev/urandom | base64)
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=freescout
DB_USERNAME=freescout
DB_PASSWORD=freescout
APP_FORCE_HTTPS=false
# The test webhook receiver runs on localhost:9000.
APP_REMOTE_HOST_WHITE_LIST=localhost,127.0.0.1,::1
EOF
    chown www-data:www-data .env
fi

# Wait for the database.
until php -r 'new PDO("mysql:host=db;dbname=freescout", "freescout", "freescout");' 2>/dev/null; do
    sleep 2
done

# Modules: copied (not symlinked) so FreeScout sees ordinary folders.
for module in ApiWebhooks OAuthApi; do
    rm -rf "Modules/$module"
    cp -R "/modules-src/$module" "Modules/$module"
done
chown -R www-data:www-data Modules storage bootstrap/cache public

su -s /bin/sh www-data -c '
    php artisan migrate --force >/dev/null
    php artisan freescout:module-install apiwebhooks >/dev/null
    php artisan freescout:module-install oauthapi >/dev/null
    php artisan freescout:clear-cache >/dev/null
'

cat > /tmp/receiver.php <<'EOF'
<?php
file_put_contents('/tmp/webhooks.log', json_encode([
    'event' => $_SERVER['HTTP_X_FREESCOUT_EVENT'] ?? '',
    'path'  => $_SERVER['REQUEST_URI'],
    'body'  => json_decode(file_get_contents('php://input'), true),
])."\n", FILE_APPEND);
echo 'ok';
EOF
touch /tmp/webhooks.log && chmod 666 /tmp/webhooks.log
php -S 0.0.0.0:9000 /tmp/receiver.php >/dev/null 2>&1 &

exec docker-php-entrypoint "$@"
