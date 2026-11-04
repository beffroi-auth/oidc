<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use Stringable;

final readonly class RedirectUri implements Stringable
{
    public string $value;

    public string $origin;

    /**
     * RFC 3986 §3.2.2, lowercased
     */
    public string $host;

    private ClientUri $uri;

    /**
     * RFC 8252 §7.3: the two IP literals, never a name
     */
    private const array LOOPBACK_HOSTS = ['127.0.0.1', '[::1]'];

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(string $value)
    {
        $this->uri = new ClientUri($value);
        $this->value = $this->uri->value;
        $this->origin = $this->uri->origin;
        $this->host = $this->uri->host;
    }

    /**
     * RFC 8252 §7.3
     *
     * Plain HTTP only: a client that registered HTTPS controls its host and is held to its port.
     */
    public function isLoopback(): bool
    {
        return $this->uri->scheme === 'http' && in_array($this->uri->host, self::LOOPBACK_HOSTS, true);
    }

    /**
     * RFC 8252 §8.3
     */
    public function isPlainHttpOnAName(): bool
    {
        return $this->uri->scheme === 'http' && ! $this->isLoopback();
    }

    /**
     * RFC 8252 §7.3
     */
    public function matchesOnAnyPort(string $requested): bool
    {
        if (! $this->isLoopback()) {
            return false;
        }
        try {
            $candidate = new self($requested);
        } catch (InvalidArgumentException) {
            return false;
        }

        return $this->uri->sameExceptThePort($candidate->uri);
    }

    /**
     * RFC 6749 §3.1.2.3
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
