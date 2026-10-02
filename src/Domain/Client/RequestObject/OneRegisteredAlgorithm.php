<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\RequestObject;

use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use function in_array;

/**
 * A client that registered one algorithm in "request_object_signing_alg" (OIDC Registration §2), which
 * is what FAPI 2.0 Message Signing asks of one: its request objects are read under that algorithm and
 * under no other, so an object signed with a weaker one the provider still takes for somebody else is
 * refused here.
 */
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
