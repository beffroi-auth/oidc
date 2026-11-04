<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * RFC 7523 §2.2, OIDC Core §9
 */
interface AssertionMethodInterface extends ClientAuthenticationMethodInterface
{
    /**
     * @return non-empty-list<non-empty-string>
     */
    public function assertionSigningAlgorithms(): array;
}
