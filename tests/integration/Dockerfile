# A disposable FreeScout for the integration tests. Not for production.
FROM php:8.2-apache

ARG FREESCOUT_VERSION=1.8.250

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpng-dev libjpeg-dev libfreetype6-dev libzip-dev libicu-dev libxml2-dev \
        libonig-dev curl ca-certificates \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli gd zip intl mbstring xml bcmath \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

# The tests change .env and rebuild the config cache between requests.
RUN echo 'opcache.revalidate_freq=0' > /usr/local/etc/php/conf.d/zz-tests.ini

RUN curl -sSL "https://github.com/freescout-help-desk/freescout/archive/refs/tags/${FREESCOUT_VERSION}.tar.gz" \
        | tar xz --strip-components=1 -C /var/www/html \
    && chown -R www-data:www-data /var/www/html

RUN sed -i 's#DocumentRoot /var/www/html#DocumentRoot /var/www/html/public#' /etc/apache2/sites-available/000-default.conf \
    && printf '<Directory /var/www/html/public>\n    AllowOverride All\n</Directory>\n' > /etc/apache2/conf-enabled/freescout.conf

COPY entrypoint.sh /usr/local/bin/freescout-entrypoint
RUN chmod +x /usr/local/bin/freescout-entrypoint

ENTRYPOINT ["freescout-entrypoint"]
CMD ["apache2-foreground"]
