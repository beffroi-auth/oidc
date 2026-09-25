<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Resource;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use function str_contains;
use Stringable;

/**
 * One resource a client asks a token for (RFC 8707 §2): an absolute URI (RFC 3986 §4.3) without a
 * fragment component, which identifies the service the access token is meant to be presented at. It is
 * an identifier and the provider never dereferences it, so a URN names a resource as well as an HTTPS
 * URL does.
 *
 * A query component is allowed, §2 recognising the cases where it is what scopes the request; a
 * fragment is not, and neither is anything a URI cannot carry.
 *
 * Compared byte for byte, as every other URI a client registers is: what a request names is what the
 * registration holds, or it is none of the resources of that client.
 */
final readonly class ResourceIndicator implements Stringable
{
    /**
     * RFC 3986 §3.1 for the scheme, then a hier-part of visible ASCII: no space, no control character,
     * nothing a URI does not carry.
     */
    private const string PATTERN = '/^[A-Za-z][A-Za-z0-9+.\-]*:[\x21-\x7E]+$/D';

    /**
     * @throws InvalidArgumentException when the value is not an absolute URI, or carries a fragment
     */
    public function __construct(
        public string $value,
    ) {
        if (str_contains($value, '#')) {
            throw new InvalidArgumentException(sprintf('The resource "%s" must not carry a fragment component (RFC 8707 section 2).', $value));
        }
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf('The resource "%s" is not an absolute URI (RFC 8707 section 2, RFC 3986 section 4.3).', $value));
        }
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
