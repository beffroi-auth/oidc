<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

final readonly class UnsignedRequestObjects implements RequestObjectSigningInterface
{
    public const string ALGORITHM = 'none';

    public function accepts(?string $algorithm, array $wired): bool
    {
        return $algorithm === self::ALGORITHM;
    }

    public function acceptsUnsigned(): bool
    {
        return true;
    }

    public function needsPublishedKeys(): bool
    {
        return false;
    }
}
