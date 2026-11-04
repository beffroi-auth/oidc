<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use LogicException as BaseLogicException;
use function sprintf;

/**
 * A client authentication method was asked to verify a client it did not authenticate here: a fault of this
 * module, never of the caller.
 */
final class ClientNotAuthenticatedHereException extends BaseLogicException implements ExceptionInterface
{
    public function __construct(Client $client, ClientAuthenticationMethodInterface $method)
    {
        parent::__construct(sprintf('The client "%s" is not authenticated by %s here.', $client->registration->clientId, $method->name()));
    }
}
