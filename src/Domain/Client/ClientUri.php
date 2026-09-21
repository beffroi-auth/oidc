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
 * A URI a client registers with the provider, whatever the provider does with it: send a browser to it
 * (RFC 6749 §3.1.2, RP-Initiated Logout §2), or post to it from the provider itself (Back-Channel Logout
 * 1.0 §2.2). Absolute, no fragment, no credentials, HTTPS; plain HTTP on a loopback host only. No custom
 * scheme, no variable loopback port (RFC 8252 §7.3). What it is for is the class that holds it.
 */
final readonly class ClientUri implements Stringable
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
            throw new InvalidArgumentException(sprintf('The URI "%s" registered for a client is not an absolute URI.', $value));
        }
        if (isset($parts['fragment'])) {
            throw new InvalidArgumentException(sprintf('The URI "%s" registered for a client must not carry a fragment (RFC 6749 §3.1.2).', $value));
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException(sprintf('The URI "%s" registered for a client must not carry credentials.', $value));
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'https' && ! ($scheme === 'http' && Issuer::isLoopbackHost(strtolower($parts['host'])))) {
            throw new InvalidArgumentException(sprintf('The URI "%s" registered for a client must use HTTPS; plain HTTP is only accepted on a loopback host.', $value));
        }

        $this->value = $value;
        $port = $parts['port'] ?? null;
        $this->origin = $scheme . '://' . strtolower($parts['host']) . ($port === null ? '' : ':' . $port);
    }

    /**
     * The registered query is kept and the parameters are added to it, every value percent-encoded
     * (RFC 3986 §2.1): what a redirection carries back (RFC 6749 §4.1.2) and what a front-channel logout
     * URI is given (Front-Channel Logout 1.0 §2).
     *
     * @param non-empty-array<string, string> $parameters
     */
    public function withParameters(array $parameters): string
    {
        $separator = str_contains($this->value, '?') ? '&' : '?';

        return $this->value . $separator . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
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
