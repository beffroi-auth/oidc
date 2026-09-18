<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use Heidi\Core\Domain\Key\PublicKeySet;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * The answer of the JWK Set endpoint (RFC 7517 §5): the published keys of the tenant, public members only,
 * cacheable for a short while; an empty set is not cached. "application/json" rather than the type of
 * RFC 7517 §8.5.1, which is what clients read.
 */
final readonly class JwkSetResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param int $maxAge how long a client may cache the set, in seconds
     */
    public function __construct(
        public PublicKeySet $keys,
        public int $maxAge,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the JWK Set is a number of seconds.');
        }
        $this->headers = [
            'Cache-Control' => $keys->isEmpty() ? 'no-store' : sprintf('public, max-age=%d', $maxAge),
        ];
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->keys->toJwks());
    }
}
