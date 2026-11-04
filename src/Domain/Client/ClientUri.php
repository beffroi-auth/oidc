<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Encoding\Host;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function http_build_query;
use function is_string;
use function parse_url;
use const PHP_QUERY_RFC3986;
use function sprintf;
use function str_contains;
use Stringable;
use function strtolower;

/**
 * A host never holds the ";" or "," RFC 3986 §3.2.2 admits: it is written into Content-Security-Policy headers.
 */
final readonly class ClientUri implements Stringable
{
    public string $value;

    public string $origin;

    /**
     * RFC 3986 §3.1, lowercased
     */
    public string $scheme;

    /**
     * RFC 3986 §3.2.2, lowercased; an IPv6 literal keeps its brackets
     */
    public string $host;

    private string $afterAuthority;

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
        if (! Host::isHost($parts['host'])) {
            throw new InvalidArgumentException(sprintf(
                'The URI "%s" registered for a client must name a host of letters, digits, hyphens and dots, or an IP address (RFC 3986 §3.2.2).',
                $value,
            ));
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'https' && ! ($scheme === 'http' && Issuer::isLoopbackHost(strtolower($parts['host'])))) {
            throw new InvalidArgumentException(sprintf(
                'The URI "%s" registered for a client must use HTTPS; plain HTTP is only accepted on a loopback host.',
                $value,
            ));
        }

        $this->value = $value;
        $port = $parts['port'] ?? null;
        $this->scheme = $scheme;
        $this->host = strtolower($parts['host']);
        $this->origin = $scheme . '://' . $this->host . ($port === null ? '' : ':' . $port);
        $this->afterAuthority = ($parts['path'] ?? '') . (isset($parts['query']) ? '?' . $parts['query'] : '');
    }

    public function sameExceptThePort(self $other): bool
    {
        return $this->scheme === $other->scheme && $this->host === $other->host && $this->afterAuthority === $other->afterAuthority;
    }

    /**
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
