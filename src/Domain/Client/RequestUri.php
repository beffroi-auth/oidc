<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function strpos;
use Stringable;
use function substr;

/**
 * OIDC Registration §2, RFC 9101 §5.2
 *
 * It may carry a fragment (OIDC Core §6.2), compared with a request but never sent to the server.
 */
final readonly class RequestUri implements Stringable
{
    public string $value;

    public ClientUri $location;

    /**
     * @throws InvalidArgumentException
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
