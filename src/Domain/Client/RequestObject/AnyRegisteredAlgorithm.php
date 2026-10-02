<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

use function in_array;

/**
 * A client that registered no "request_object_signing_alg" (OIDC Registration §2): its request objects
 * are read under any algorithm the provider is wired with. Never unsigned, whatever the default of the
 * specification is read to be: an unsigned object is the named exception of decision 0006 and is
 * registered, never fallen into.
 */
final readonly class AnyRegisteredAlgorithm implements RequestObjectSigningInterface
{
    public function accepts(?string $algorithm, array $wired): bool
    {
        return $algorithm !== null && in_array($algorithm, $wired, true);
    }

    public function acceptsUnsigned(): bool
    {
        return false;
    }

    public function needsPublishedKeys(): bool
    {
        return false;
    }
}
