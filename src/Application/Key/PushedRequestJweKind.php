<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;

/**
 * A request a client pushes, encrypted to a key of the provider (RFC 9126 §2, RFC 9101 §6.1). A client
 * that read the JWK Set may be pushing such a request at any moment, and the reference it gets back lives
 * as long as the endpoint says: an encryption key stays openable for that long after it stopped being the
 * active one. The lifetime is read from the endpoint so that the two cannot disagree, which is the rule
 * issue #155 asks of every kind.
 */
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
