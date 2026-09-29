<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use DateTimeImmutable;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * A client of a tenant as whoever runs the deployment sees it (decision 0009): where it came from, what
 * it calls itself, and the two dates a client that registered itself has. It is what a list of clients
 * is made of, and it says nothing a request is served against.
 *
 * **The source names itself.** A client a deployment declared and one that registered itself are the same
 * client to every rule of the protocol, and are not the same thing at all to whoever answers for the
 * deployment: one is a line of `heidi.yaml` and is deleted by deleting that line, the other is a row and
 * is deleted by deleting the row. So the source is carried here, as the source gives it, and a source
 * wired later appears in the list without anything learning that there are several.
 *
 * The dates are null together for a source that holds declarations: a declaration was not registered on a
 * day and has no history (decision 0009, `ClientRecord`).
 */
final readonly class InventoriedClient
{
    /**
     * @param non-empty-string $source what the source that holds this client calls itself
     * @param string|null $clientName what the client calls itself (OIDC Registration §2), null for one that registered no name
     * @param DateTimeImmutable|null $registeredAt when this provider registered it, null for a client it did not register
     * @param DateTimeImmutable|null $lastUsedAt when somebody last used it, null for one never used and for one this provider did not register
     *
     * @throws InvalidArgumentException when it names no client, or the two dates are the wrong way round
     */
    public function __construct(
        public string $source,
        public string $clientId,
        public ?string $clientName = null,
        public ?DateTimeImmutable $registeredAt = null,
        public ?DateTimeImmutable $lastUsedAt = null,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('A client of a tenant carries the identifier it is known by (RFC 7591 section 2).');
        }
        if ($registeredAt !== null && $lastUsedAt !== null && $lastUsedAt < $registeredAt) {
            throw new InvalidArgumentException('A client was not used before it was registered.');
        }
    }

    /**
     * Whether this provider is what registered it, which is what says it can be deleted here at all: a
     * client a deployment declared goes away when the declaration does, and nothing of this provider
     * takes it back.
     */
    public function wasRegisteredHere(): bool
    {
        return $this->registeredAt !== null;
    }
}
