<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * An event that counts as a use of its client, which keeps the client from deletion; a refusal never counts.
 */
interface ClientInUseInterface extends ConcernsAClientInterface
{
}
