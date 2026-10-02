<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The types of authorization detail the wiring gave the provider (RFC 9396 §2), which is what a client
 * may register, what a request may name, and what the discovery document announces (§10). Derived from
 * what is wired and never listed beside it (issue #98).
 *
 * A deployment that wires none serves none: rich authorization requests are what a domain asks for, and
 * no type is universal, so a provider that was given no type refuses every "authorization_details" it is
 * sent and announces nothing rather than an empty list.
 */
interface ServedAuthorizationDetailTypesInterface
{
    /**
     * @throws InvalidArgumentException when two wired types answer for one "type"
     *
     * @return list<non-empty-string> each once, in the order the types are wired
     */
    public function servedAuthorizationDetailTypes(): array;
}
