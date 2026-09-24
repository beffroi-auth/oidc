<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function array_map;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

/**
 * The names of client authentication methods, read from the methods themselves. Every place that has to
 * say them, each endpoint the discovery document describes and the message a registration naming an
 * unwired method is refused with, reads them here: a method names itself and nothing writes that reading
 * again.
 */
final readonly class MethodNames
{
    /**
     * @param list<ClientAuthenticationMethodInterface> $methods
     *
     * @return ($methods is non-empty-list<ClientAuthenticationMethodInterface> ? non-empty-list<non-empty-string> : list<non-empty-string>)
     */
    public static function of(array $methods): array
    {
        return array_map(static fn (ClientAuthenticationMethodInterface $method): string => $method->name(), $methods);
    }
}
