<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_find;
use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;

final readonly class PresentedCredentials
{
    /**
     * @param non-empty-list<PresentedMethod> $presented all reading the same thing and naming the same client
     */
    public function __construct(
        private array $presented,
    ) {
    }

    public function clientId(): string
    {
        return $this->presented[0]->clientId;
    }

    public function first(): AuthenticationMethodInterface
    {
        return $this->presented[0]->method;
    }

    public function registeredBy(Client $client): ?AuthenticationMethodInterface
    {
        $registered = $client->registration->authenticationMethod->name();

        return array_find(
            $this->presented,
            static fn (PresentedMethod $presented): bool => $presented->name() === $registered,
        )?->method;
    }
}
