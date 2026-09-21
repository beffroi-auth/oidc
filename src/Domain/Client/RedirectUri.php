<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

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

    private ClientUri $uri;

    public function __construct(string $value)
    {
        $this->uri = new ClientUri($value);
        $this->value = $this->uri->value;
        $this->origin = $this->uri->origin;
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
     * RFC 6749 §4.1.2, see ClientUri.
     *
     * @param non-empty-array<string, string> $parameters
     */
    public function withParameters(array $parameters): string
    {
        return $this->uri->withParameters($parameters);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
