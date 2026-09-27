<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use Stringable;

/**
 * A redirection URI registered for a client (RFC 6749 §3.1.2, RP-Initiated Logout §2), compared byte for
 * byte (RFC 6749 §3.1.2.3, RFC 9700 §4.1.3). What may be registered at all is ClientUri; this is what a
 * redirection does with it, matching a request and carrying a response back.
 *
 * A redirection in plain HTTP on one of the two loopback IP literals is the loopback interface of a native
 * client (RFC 8252 §7.3), and the port of such a URI is the one named exception to the exact match
 * (architecture §8): a native client listens on a port the operating system hands it when it starts, so it
 * cannot register the port it will be reachable on. Nothing else varies.
 *
 * Both questions are asked by whoever may claim the exception, which is the registration of a public client
 * (ClientRegistration) and no option of a deployment: this class says what a URI is, never who may relax
 * what.
 */
final readonly class RedirectUri implements Stringable
{
    public string $value;

    /**
     * RFC 6454 §3.2, see ClientUri.
     */
    public string $origin;

    private ClientUri $uri;

    /**
     * RFC 8252 §7.3: the two loopback IP literals, and nothing else.
     */
    private const array LOOPBACK_HOSTS = ['127.0.0.1', '[::1]'];

    /**
     * @throws InvalidArgumentException when it is not a URI a client may register
     */
    public function __construct(string $value)
    {
        $this->uri = new ClientUri($value);
        $this->value = $this->uri->value;
        $this->origin = $this->uri->origin;
    }

    /**
     * Whether this is the loopback interface of a native client (RFC 8252 §7.3): plain HTTP on one of the
     * two IP literals. A client that registered HTTPS registered a host it controls and the port with it,
     * so it is held to both.
     */
    public function isLoopback(): bool
    {
        return $this->uri->scheme === 'http' && in_array($this->uri->host, self::LOOPBACK_HOSTS, true);
    }

    /**
     * RFC 8252 §8.3: whether this URI is in plain HTTP somewhere a native client must not put one. The
     * specification requires the IP literal and forbids the name, "localhost" included, because a name is
     * resolved: what answers for it on the machine of the user is not something the client chose, and a
     * redirection carrying a code is not a thing to hand to whatever answers. Which URIs may be in plain
     * HTTP at all is the rule of every URI a client registers (ClientUri); this says which of those a
     * native client may be sent back to.
     */
    public function isPlainHttpOnAName(): bool
    {
        return $this->uri->scheme === 'http' && ! $this->isLoopback();
    }

    /**
     * RFC 8252 §7.3: the same URI on whatever port the browser reached the client on, which is the one
     * named exception to the byte for byte comparison above. Everything else is compared as it is
     * everywhere else: another path, another host and a name in place of a literal are not this URI.
     *
     * Only a loopback URI answers true to this, and only the registration of a public client asks
     * (ClientRegistration::hasRedirectUri()): the port a request names is read from a request, so nothing
     * a confidential client registers is relaxed by it.
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
