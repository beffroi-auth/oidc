<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;

final readonly class RequestObjectJweKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private RequestObjectValidator $objects,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Encryption;
    }

    public function longestLifetime(Tenant $tenant): DateInterval
    {
        return $this->objects->maximumLifetime;
    }
}
