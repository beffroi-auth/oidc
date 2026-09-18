<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\IssuedJwsKindInterface;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;

/**
 * The ID token (OIDC Core §2). The lifetime is read from the issuer so that the two cannot disagree.
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
