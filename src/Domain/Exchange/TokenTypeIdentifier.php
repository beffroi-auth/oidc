<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Exchange;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * A token type identifier (RFC 8693 §3): the URI that says what kind of token a request presents and what
 * kind it asks for. It is a URI and never a bare word, because the registry of §3 names every type by one
 * and an extension names its own that way (RFC 6755).
 *
 * The one this provider reads and writes is the access token; a type it serves is a class wired into the
 * provider (PresentedTokenTypeInterface) and this is only the name such a class gives itself.
 */
final readonly class TokenTypeIdentifier implements Stringable
{
    /**
     * RFC 8693 §3: the access tokens of RFC 6749, which is what this provider issues and what it reads
     * back as a subject or as an actor token.
     */
    public const string ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

    /**
     * RFC 3986 §3: a scheme and something after it, no fragment, nothing relative.
     */
    private const string PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    public function __construct(
        public string $value,
    ) {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The token type identifier "%s" must be an absolute URI without a fragment (RFC 8693 section 3).',
                $value,
            ));
        }
    }

    public static function accessToken(): self
    {
        return new self(self::ACCESS_TOKEN);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
