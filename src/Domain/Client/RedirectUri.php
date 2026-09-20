<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function http_build_query;
use const PHP_QUERY_RFC3986;
use function str_contains;
use Stringable;

/**
 * A redirection URI registered for a client (RFC 6749 §3.1.2, RP-Initiated Logout §2), compared byte for
 * byte (RFC 6749 §3.1.2.3, RFC 9700 §4.1.3). What may be registered at all is ClientUri; this is what a
 * redirection does with it, matching a request and carrying a response back.
 */
final readonly class RedirectUri implements Stringable
{
    public string $value;

    /**
     * RFC 6454 §3.2, see ClientUri.
     */
    public string $origin;

    public function __construct(string $value)
    {
        $uri = new ClientUri($value);
        $this->value = $uri->value;
        $this->origin = $uri->origin;
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
