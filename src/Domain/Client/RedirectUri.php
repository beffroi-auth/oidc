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
 * A redirection URI registered for a client (RFC 6749 §3.1.2, RP-Initiated Logout §2), compared byte for
 * byte (RFC 6749 §3.1.2.3, RFC 9700 §4.1.3). Absolute, no fragment, HTTPS; plain HTTP on a loopback host
 * only. No custom scheme, no variable loopback port (RFC 8252 §7.3).
 */
final readonly class RedirectUri implements Stringable
{
    public string $value;

    /**
     * RFC 6454 §3.2: the scheme, the host and the port, which is what a Content-Security-Policy source
     * expression names when a page is allowed to post here (Form Post Response Mode §2).
     */
    public string $origin;

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
        $port = $parts['port'] ?? null;
        $this->origin = $scheme . '://' . strtolower($parts['host']) . ($port === null ? '' : ':' . $port);
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
     * RFC 6749 §4.1.2: the registered query retained, every value percent-encoded (RFC 3986 §2.1).
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
