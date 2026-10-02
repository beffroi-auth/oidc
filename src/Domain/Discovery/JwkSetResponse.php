<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Discovery;

use Beffroi\Core\Domain\Key\PublicKeySet;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidArgumentException;
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
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public function __construct(
        public PublicKeySet $keys,
        public int $maxAge,
    ) {
        self::assertCacheLifetime($maxAge);
        $this->headers = [
            'Cache-Control' => $keys->isEmpty() ? 'no-store' : sprintf('public, max-age=%d', $maxAge),
        ];
    }

    /**
     * How long a client may cache the set. The handler that holds the number refuses it at boot and the
     * answer refuses it again when one is built by hand, which is one rule and is therefore written
     * here alone.
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public static function assertCacheLifetime(int $maxAge): void
    {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the JWK Set is a number of seconds.');
        }
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->keys->toJwks());
    }
}
