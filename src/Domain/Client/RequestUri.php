<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function strpos;
use Stringable;
use function substr;

/**
 * A URL a request object of a client is read back from (OIDC Registration §2 "request_uris", RFC 9101 §5.2):
 * a kind of its own, as RedirectUri is, because what it accepts is not what a redirection accepts.
 *
 * **It may carry a fragment, and OIDC Core §6.2 says what one means**: the base64url-encoded SHA-256 hash of
 * the content behind the URL, so that a provider may keep what it fetched and read it again without asking.
 * ClientUri refuses every fragment for the reason a redirection has (RFC 6749 §3.1.2), and nothing is
 * redirected here: the provider fetches. So what may be registered at all stays ClientUri's rule, applied to
 * the URI without its fragment, and the fragment is this class's.
 *
 * Whether the hash matches what came back is another question, which §6.2 leaves optional and which nothing
 * here asks.
 *
 * The two strings are both needed and are not the same one. What a request names is compared byte for byte
 * with what was registered, fragment included (`ClientRegistration::registeredRequestUri()`), and what the
 * provider reads is the URL without it: a fragment is what a client keeps and never what a server is sent
 * (RFC 3986 §3.5).
 */
final readonly class RequestUri implements Stringable
{
    /**
     * As it was registered, the fragment included.
     */
    public string $value;

    /**
     * The URL the object is read back from, which is every rule of a URI a client registers (ClientUri).
     */
    public ClientUri $location;

    /**
     * @throws InvalidArgumentException when it is not a URI a client may register
     */
    public function __construct(string $value)
    {
        $fragment = strpos($value, '#');
        $this->location = new ClientUri($fragment === false ? $value : substr($value, 0, $fragment));
        $this->value = $value;
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
