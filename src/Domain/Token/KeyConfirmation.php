<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;

/**
 * RFC 9449 §6.1, RFC 7638 §3
 */
final readonly class KeyConfirmation implements ConfirmationInterface
{
    public const string MEMBER = 'jkt';

    /**
     * RFC 9449 §5
     */
    public const string SCHEME = 'DPoP';

    /**
     * RFC 7638 §3.1
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

    public function toMembers(): array
    {
        return [
            self::MEMBER => $this->thumbprint,
        ];
    }

    public function toClaims(): array
    {
        return [
            ConfirmationInterface::CLAIM => $this->toMembers(),
        ];
    }

    public function matches(ConfirmationInterface $other): bool
    {
        return $other->member() === self::MEMBER && hash_equals($this->thumbprint, $other->value());
    }
}
