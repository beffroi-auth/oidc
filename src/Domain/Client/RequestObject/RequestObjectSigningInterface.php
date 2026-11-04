<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

/**
 * OIDC Registration §2, RFC 9101 §6.1
 */
interface RequestObjectSigningInterface
{
    /**
     * @param list<non-empty-string> $wired the algorithms the provider verifies signatures with
     */
    public function accepts(?string $algorithm, array $wired): bool;

    public function acceptsUnsigned(): bool;

    public function needsPublishedKeys(): bool;
}
