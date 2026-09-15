<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function http_build_query;
use function is_string;
use function parse_url;
use const PHP_QUERY_RFC3986;
use function sprintf;
use function str_contains;
use Stringable;
use function strtolower;

/**
 * A redirection URI registered for a client, for the authorization response (RFC 6749 §3.1.2) or for the
 * end of a session (OIDC RP-Initiated Logout 1.0 §2). It is kept byte for byte: the request is compared to
 * it with a simple string comparison (RFC 6749 §3.1.2.3, RFC 3986 §6.2.1), never with a pattern, never
 * after a normalisation (RFC 9700 §4.1.3).
 *
 * The URI is absolute, without a fragment (RFC 6749 §3.1.2) and over HTTPS. The one named exception is
 * plain HTTP on a loopback host, the same one the issuer allows, so that a client under development can
 * register "http://localhost:8000/login/check". Custom schemes and the variable loopback port of native
 * applications (RFC 8252 §7.3) are not accepted: they are out of the scope of the first spike.
 */
final readonly class RedirectUri implements Stringable
{
    public string $value;

    public function __construct(string $value)
    {
        $parts = parse_url($value);
        if ($parts === false || ! isset($parts['scheme'], $parts['host']) || ! is_string($parts['host'])) {
            throw new InvalidArgumentException(sprintf('The redirect URI "%s" is not an absolute URI.', $value));
        }
        if (isset($parts['fragment'])) {
            throw new InvalidArgumentException(sprintf('The redirect URI "%s" must not carry a fragment (RFC 6749 §3.1.2).', $value));
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException(sprintf('The redirect URI "%s" must not carry credentials.', $value));
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'https' && ! ($scheme === 'http' && Issuer::isLoopbackHost(strtolower($parts['host'])))) {
            throw new InvalidArgumentException(sprintf('The redirect URI "%s" must use HTTPS; plain HTTP is only accepted on a loopback host.', $value));
        }

        $this->value = $value;
    }

    /**
     * RFC 6749 §3.1.2.3: simple string comparison.
     */
    public function matches(string $requested): bool
    {
        return $this->value === $requested;
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    /**
     * The URI with response parameters added to its query component (RFC 6749 §4.1.2), the registered
     * query retained, every value percent-encoded (RFC 3986 §2.1) so that every parser reads it the same way.
     *
     * @param non-empty-array<string, string> $parameters
     */
    public function withParameters(array $parameters): string
    {
        $separator = str_contains($this->value, '?') ? '&' : '?';

        return $this->value . $separator . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
