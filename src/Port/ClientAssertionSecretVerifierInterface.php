<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * OIDC Core §9
 */
interface ClientAssertionSecretVerifierInterface
{
    /**
     * @param non-empty-list<non-empty-string> $algorithms
     *
     * @throws InvalidJwtException
     */
    public function verify(UnverifiedJwt $assertion, SharedClientSecret $secret, array $algorithms): void;
}
