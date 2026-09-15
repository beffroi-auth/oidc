<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use Heidi\Core\Domain\Key\PublicKeySet;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * The answer of the JWK Set endpoint (RFC 7517 §5, OIDC Discovery §3 "jwks_uri"): the public keys of the
 * tenant that may still have signed a token in circulation, the active one and those retiring, each with
 * "kid", "kty", "alg" and "use" (RFC 7517 §4), never a private member. Public and cacheable for a short
 * while: the document is the same for everybody, and a client that meets an unknown "kid" fetches it
 * again on its own (Symfony's oidc_login does, with a cooldown), so a rotation in spike 2 does not wait
 * for the cache to expire. A set without any key is not cached at all, so that the first key generated is
 * seen at once.
 *
 * "application/json" rather than the "application/jwk-set+json" of RFC 7517 §8.5.1 because that is what
 * every provider in the wild serves and what every client library reads without looking twice.
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

    /**
     * @return string the JWK Set as a JSON object with its "keys" list (RFC 7517 §5.1)
     */
    public function toJson(): string
    {
        return JwtPayload::encode($this->keys->toJwks());
    }
}
