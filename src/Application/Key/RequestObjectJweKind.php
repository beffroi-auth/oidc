<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;

/**
 * A request object encrypted to a key of the provider (RFC 9101 §6.1, OIDC Core §6.1). What bounds the
 * retirement of an encryption key is not what the provider issued, which is nothing here, but what a
 * client may still be sending it: an object stands as long as the provider accepts one to stand, so a key
 * it may have been encrypted to stays openable for that long after it stopped being the active one. The
 * lifetime is read from the validator so that the two cannot disagree.
 */
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
