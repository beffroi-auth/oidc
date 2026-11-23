<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\DomainEventInterface;

/**
 * Names the client an act concerns by its identifier, or none: a refusal names the client a request named only when the
 * tenant holds it (decision 0062).
 */
interface MayConcernAClientInterface extends DomainEventInterface
{
    public ?string $clientId { get; }
}
