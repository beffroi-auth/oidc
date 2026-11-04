<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PublicKeySetProviderInterface;
use Beffroi\Oidc\Domain\Discovery\JwkSetResponse;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 7517 §5
 */
final readonly class JwksHandler
{
    /**
     * The staging window of a key rotation derives from it.
     */
    public const int DEFAULT_MAX_AGE = 300;

    /**
     * @param int $maxAge in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public function __construct(
        private PublicKeySetProviderInterface $keys,
        private int $maxAge = self::DEFAULT_MAX_AGE,
    ) {
        JwkSetResponse::assertCacheLifetime($maxAge);
    }

    public function handle(Tenant $tenant): JwkSetResponse
    {
        return new JwkSetResponse($this->keys->publicKeys($tenant), $this->maxAge);
    }
}
