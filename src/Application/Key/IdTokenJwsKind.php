<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;

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
