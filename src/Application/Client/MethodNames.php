<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_map;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

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
