<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * The name of a grant type (RFC 6749 appendix A.10, RFC 7591 §2 "grant_types"), compared byte for byte:
 * a name of the IANA "OAuth Authorization Grant Types" registry, or the absolute URI an extension grant
 * is named by (RFC 6749 §4.5, RFC 6755). It carries the shape of a name and nothing else; which names
 * exist is what the provider is wired with, and no list of them is kept anywhere.
 */
final readonly class GrantTypeName implements Stringable
{
    /**
     * RFC 6749 appendix A.10: grant-name = 1*name-char.
     */
    private const string NAME_PATTERN = '/^[A-Za-z0-9._-]+$/D';

    /**
     * RFC 3986 §4.3: a scheme, a colon and something after it, no fragment.
     */
    private const string ABSOLUTE_URI_PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    public function __construct(
        public string $value,
    ) {
        if (preg_match(self::NAME_PATTERN, $value) !== 1 && preg_match(self::ABSOLUTE_URI_PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf(
                '"%s" names no grant: a grant type is a name of the IANA registry or the absolute URI of an extension grant (RFC 6749 appendix A.10 and section 4.5).',
                $value,
            ));
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
