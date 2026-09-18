<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\IssuedJwsKindInterface;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Port\ClientRepositoryInterface;

/**
 * The self-contained access token (RFC 9068, "at+jwt"), a JWS the tenant issues only when a client of its
 * is registered for that shape (architecture §4.6): an opaque access token depends on no key and does not
 * hold a retirement back. The lifetime is read from the issuer so that the two cannot disagree.
 */
final readonly class AccessTokenJwsKind implements IssuedJwsKindInterface
{
    public function __construct(
        private JwtAccessTokenIssuer $issuer,
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->clients->issuesAccessTokensIn($tenant, AccessTokenFormat::Jwt) ? $this->issuer->lifetime : null;
    }
}
