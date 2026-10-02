<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Port\RegisteredAccessTokenShapesInterface;

/**
 * The "at+jwt" access token (RFC 9068), issued only when a client of the tenant is registered for that
 * shape (architecture §4.6). Both the shape and the lifetime are read from the issuer that writes them,
 * so that nothing here names either again.
 */
final readonly class AccessTokenJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private JwtAccessTokenIssuer $issuer,
        private RegisteredAccessTokenShapesInterface $shapes,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->shapes->issuesAccessTokensIn($tenant, $this->issuer) ? $this->issuer->lifetime : null;
    }
}
