<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;

/**
 * Decision 0009
 */
final class ClientRegistrationNotOfferedException extends RuntimeException implements ExceptionInterface
{
    public const int STATUS_CODE = 404;

    public function __construct()
    {
        parent::__construct('This tenant registers no client (decision 0009).');
    }
}
