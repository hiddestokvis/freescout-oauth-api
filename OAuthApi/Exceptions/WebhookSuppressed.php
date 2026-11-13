<?php

namespace Modules\OAuthApi\Exceptions;

/**
 * Thrown to stop a webhook delivery the API & Webhooks module would
 * otherwise make. See WebhookManager::guardDelivery().
 */
class WebhookSuppressed extends \RuntimeException
{
}
