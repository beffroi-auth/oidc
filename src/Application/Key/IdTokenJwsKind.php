<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\IssuedJwsKindInterface;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;

/**
 * The ID token, a JWS every tenant issues (OIDC Core §2), alive for the lifetime its issuer writes in
 * "exp": read from the issuer so that the retirement of a key and the tokens it signed cannot disagree.
 */
final readonly class IdTokenJwsKind implements IssuedJwsKindInterface
{
    public function __construct(
        private JwtIdTokenIssuer $issuer,
    ) {
    }

    public function longestLifetime(Tenant $tenant): DateInterval
    {
        return $this->issuer->lifetime;
    }
}
