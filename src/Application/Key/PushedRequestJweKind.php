<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;

final readonly class PushedRequestJweKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private PushedAuthorizationHandler $endpoint,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Encryption;
    }

    public function longestLifetime(Tenant $tenant): DateInterval
    {
        return $this->endpoint->lifetime;
    }
}
