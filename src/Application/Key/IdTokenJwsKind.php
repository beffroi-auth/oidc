<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Key\KeyUse;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\KeyBoundArtifactInterface;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;

/**
 * The ID token (OIDC Core §2). The lifetime is read from the issuer so that the two cannot disagree.
 */
final readonly class IdTokenJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private JwtIdTokenIssuer $issuer,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): DateInterval
    {
        return $this->issuer->lifetime;
    }
}
