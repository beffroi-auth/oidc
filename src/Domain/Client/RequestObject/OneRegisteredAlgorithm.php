<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use function in_array;

final readonly class OneRegisteredAlgorithm implements RequestObjectSigningInterface
{
    public function __construct(
        public SignatureAlgorithmInterface $algorithm,
    ) {
    }

    public function accepts(?string $algorithm, array $wired): bool
    {
        return $algorithm === $this->algorithm->name() && in_array($algorithm, $wired, true);
    }

    public function acceptsUnsigned(): bool
    {
        return false;
    }

    public function needsPublishedKeys(): bool
    {
        return true;
    }
}
