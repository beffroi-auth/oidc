<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_any;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

/**
 * RFC 8705 §3
 */
final readonly class CertificateBinding
{
    /**
     * @param list<ClientAuthenticationMethodInterface> $methods
     */
    public static function servedBy(array $methods): bool
    {
        return array_any(
            $methods,
            static fn (ClientAuthenticationMethodInterface $method): bool => $method instanceof CertificateBindingMethodInterface,
        );
    }
}
