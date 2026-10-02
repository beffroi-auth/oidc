<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_find;
use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * What one request presents as its client authentication: the methods that read it, which are one
 * mechanism of RFC 6749 §2.3, and the one client they all name. Several methods come back when several
 * read the one credential the request carries, as the two mutual-TLS methods of RFC 8705 §2 both read
 * the certificate of the connection; the registration of the client is the only thing that tells them
 * apart, and it is asked here.
 */
final readonly class PresentedCredentials
{
    /**
     * @param non-empty-list<PresentedMethod> $presented all reading the same thing and naming the same client
     */
    public function __construct(
        private array $presented,
    ) {
    }

    /**
     * The client every one of them names, which the authenticator looks up.
     */
    public function clientId(): string
    {
        return $this->presented[0]->clientId;
    }

    /**
     * The method the audit trail names when the request is refused before a client is known: the first
     * that read the request, in the order the methods are wired.
     */
    public function first(): AuthenticationMethodInterface
    {
        return $this->presented[0]->method;
    }

    /**
     * The one of them the client registered, null when it registered another method altogether.
     */
    public function registeredBy(Client $client): ?AuthenticationMethodInterface
    {
        $registered = $client->registration->authenticationMethod->name();

        return array_find(
            $this->presented,
            static fn (PresentedMethod $presented): bool => $presented->name() === $registered,
        )?->method;
    }
}
