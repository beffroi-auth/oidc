<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use LogicException as BaseLogicException;
use function sprintf;

/**
 * A client authentication method was asked to verify a client it did not authenticate here: the
 * authenticator picked the method because it read the request, so a request that no longer carries what
 * it read, or a client kept in a shape the method does not verify, is a fault of this module and never
 * of the caller.
 */
final class ClientNotAuthenticatedHereException extends BaseLogicException implements ExceptionInterface
{
    public function __construct(Client $client, ClientAuthenticationMethodInterface $method)
    {
        parent::__construct(sprintf('The client "%s" is not authenticated by %s here.', $client->registration->clientId, $method->name()));
    }
}
