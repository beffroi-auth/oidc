<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;

/**
 * Verifies the MAC of a client assertion against the secret the client registered (OIDC Core §9,
 * "client_secret_jwt").
 */
interface ClientAssertionSecretVerifierInterface
{
    /**
     * @param non-empty-list<non-empty-string> $algorithms the "alg" the MAC may carry
     *
     * @throws InvalidJwtException when the algorithm is not one of those or the MAC does not verify
     */
    public function verify(UnverifiedJwt $assertion, SharedClientSecret $secret, array $algorithms): void;
}
