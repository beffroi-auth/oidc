<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Oidc\Domain\Discovery\JwkSetResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The JWK Set endpoint (RFC 7517 §5, architecture §4.8): the published keys of a tenant.
 */
final readonly class JwksHandler
{
    /**
     * The staging window of a rotation derives from it (architecture §3.3).
     */
    public const int DEFAULT_MAX_AGE = 300;

    /**
     * @param int $maxAge how long a client may cache the set, in seconds
     */
    public function __construct(
        private SigningKeyProviderInterface $keys,
        private int $maxAge = self::DEFAULT_MAX_AGE,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the JWK Set is a number of seconds.');
        }
    }

    public function handle(Tenant $tenant): JwkSetResponse
    {
        return new JwkSetResponse($this->keys->publicKeys($tenant), $this->maxAge);
    }
}
