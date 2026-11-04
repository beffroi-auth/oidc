<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * RFC 6749 §2.3, OIDC Core §9
 */
interface ClientAuthenticationMethodInterface
{
    /**
     * @return non-empty-string
     */
    public function name(): string;

    public function authenticatesClient(): bool;
}
