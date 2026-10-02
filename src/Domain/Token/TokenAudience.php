<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function array_is_list;
use ArrayIterator;
use function count;
use Countable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function is_array;
use function is_string;
use IteratorAggregate;
use Traversable;

/**
 * Who an access token is addressed to (RFC 7519 §4.1.3): the resources the request asked it for
 * (RFC 8707 §2), or the client itself when it asked for none. Written once here, because the two shapes
 * of access token write it, the introspection response renders it and the verifier reads it back, and
 * four places that must agree on what "aud" is are one place.
 *
 * "aud" is the audience and never the client: what names the client is "client_id" (RFC 9068 §2.2),
 * which is written beside it whatever the audience says.
 *
 * @implements IteratorAggregate<int, string>
 */
final readonly class TokenAudience implements Countable, IteratorAggregate
{
    /**
     * @var non-empty-list<string> in the order they were first seen
     */
    public array $values;

    /**
     * @param list<string> $values at least one; a value named twice counts once
     *
     * @throws InvalidArgumentException when the audience is empty, or holds something that is not text
     */
    public function __construct(array $values)
    {
        $kept = [];
        foreach ($values as $value) {
            if ($value === '') {
                throw new InvalidArgumentException('An audience names something (RFC 7519 section 4.1.3).');
            }
            if (! in_array($value, $kept, true)) {
                $kept[] = $value;
            }
        }
        if ($kept === []) {
            throw new InvalidArgumentException('An access token is addressed to at least one audience (RFC 7519 section 4.1.3).');
        }
        $this->values = $kept;
    }

    /**
     * RFC 8707 §2: a token is audience-restricted to the resources the request named. A request that
     * named none asks for nothing beyond the provider itself, and its token is addressed to the client
     * that asked for it, which is what a client of OpenID Connect presents at the UserInfo endpoint and
     * introspects. Nothing is defaulted to the resources the client registered: a token valid at
     * several resources is valid at each of them (RFC 8707 §3), so it is asked for and never assumed.
     */
    public static function of(Client $client, ?ResourceIndicators $resources): self
    {
        return $resources === null ? new self([$client->registration->clientId]) : new self($resources->values());
    }

    /**
     * RFC 7519 §4.1.3: an "aud" claim or member is a single string or a list of strings.
     *
     * @throws InvalidArgumentException when it is neither
     */
    public static function fromClaim(mixed $aud): self
    {
        if (is_string($aud)) {
            return new self([$aud]);
        }
        if (! is_array($aud) || ! array_is_list($aud)) {
            throw new InvalidArgumentException('An "aud" claim is a string or a list of strings (RFC 7519 section 4.1.3).');
        }
        foreach ($aud as $value) {
            if (! is_string($value)) {
                throw new InvalidArgumentException('An "aud" claim is a string or a list of strings (RFC 7519 section 4.1.3).');
            }
        }

        return new self($aud);
    }

    /**
     * RFC 7519 §4.1.3: one audience is written as a string, several as a list, which is how every
     * reader of an "aud" expects to find it.
     *
     * @return string|non-empty-list<string>
     */
    public function claim(): string|array
    {
        return count($this->values) === 1 ? $this->values[0] : $this->values;
    }

    public function has(string $value): bool
    {
        return in_array($value, $this->values, true);
    }

    public function equals(self $other): bool
    {
        return $this->values === $other->values;
    }

    public function count(): int
    {
        return count($this->values);
    }

    /**
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->values);
    }
}
