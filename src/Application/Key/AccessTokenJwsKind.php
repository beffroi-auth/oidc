<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Key\KeyUse;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\KeyBoundArtifactInterface;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Port\ClientRepositoryInterface;

/**
 * The "at+jwt" access token (RFC 9068), issued only when a client of the tenant is registered for that
 * shape (architecture §4.6). The lifetime is read from the issuer so that the two cannot disagree.
 */
final readonly class AccessTokenJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private JwtAccessTokenIssuer $issuer,
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->clients->issuesAccessTokensIn($tenant, AccessTokenFormat::Jwt) ? $this->issuer->lifetime : null;
    }
}
