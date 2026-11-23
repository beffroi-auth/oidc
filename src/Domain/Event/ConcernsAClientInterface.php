<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * Names the client by its identifier, never the object: a client carries the reader of its "jwks_uri", which no
 * broker can be sent.
 */
interface ConcernsAClientInterface extends MayConcernAClientInterface
{
    public string $clientId { get; }
}
