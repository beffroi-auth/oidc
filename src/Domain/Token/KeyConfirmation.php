<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function hash_equals;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;

/**
 * A token bound to the key its client proved possession of (RFC 9449 §6.1), named by the JWK thumbprint
 * of RFC 7638 §3: the SHA-256 of the canonical form of the public key, base64url without padding. The
 * token is presented under the "DPoP" scheme from then on, and every request that carries it carries a
 * proof signed with that key (§7.1).
 */
final readonly class KeyConfirmation implements ConfirmationInterface
{
    public const string MEMBER = 'jkt';

    /**
     * RFC 9449 §5: the scheme of a token bound to a key, the "token_type" of the response that hands it
     * out and the scheme of the Authorization header that presents it again.
     */
    public const string SCHEME = 'DPoP';

    /**
     * RFC 7638 §3.1: the base64url of a SHA-256, 43 characters and no padding.
     */
    private const string THUMBPRINT = '/^[A-Za-z0-9_-]{43}$/D';

    public function __construct(
        public string $thumbprint,
    ) {
        if (preg_match(self::THUMBPRINT, $thumbprint) !== 1) {
            throw new InvalidArgumentException('A key confirmation names a key by its JWK thumbprint, the base64url of a SHA-256 (RFC 7638 section 3.1).');
        }
    }

    public function member(): string
    {
        return self::MEMBER;
    }

    public function value(): string
    {
        return $this->thumbprint;
    }

    public function scheme(): string
    {
        return self::SCHEME;
    }

    public function toClaims(): array
    {
        return [
            Confirmations::CLAIM => [
                self::MEMBER => $this->thumbprint,
            ],
        ];
    }

    public function matches(ConfirmationInterface $other): bool
    {
        return $other->member() === self::MEMBER && hash_equals($this->thumbprint, $other->value());
    }
}
