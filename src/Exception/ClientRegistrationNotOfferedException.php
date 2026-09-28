<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException;

/**
 * The tenant registers nobody (decision 0009): closed is the default, and a closed tenant has no
 * registration endpoint rather than one that reads a request and refuses it. That is what the discovery
 * document of such a tenant says by announcing no "registration_endpoint", and a 404 is what says the
 * same thing on the wire.
 *
 * It carries no error of the protocol because it answers for none: nothing of the request was read, and
 * nothing in it would have changed the answer.
 */
final class ClientRegistrationNotOfferedException extends RuntimeException implements ExceptionInterface
{
    public const int STATUS_CODE = 404;

    public function __construct()
    {
        parent::__construct('This tenant registers no client (decision 0009).');
    }
}
