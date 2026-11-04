<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

use function in_array;

/**
 * No "request_object_signing_alg" registered: any algorithm the provider is wired with, never "none".
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
