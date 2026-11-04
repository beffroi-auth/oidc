<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Discovery;

use Beffroi\Core\Domain\Key\PublicKeySet;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * RFC 7517 §5
 *
 * Served as "application/json" rather than the type of RFC 7517 §8.5.1, which is what clients read.
 */
final readonly class JwkSetResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @throws InvalidArgumentException
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
     * @throws InvalidArgumentException
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
