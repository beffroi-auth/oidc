<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedGrantsInterface;

interface FlowShapeInterface
{
    /**
     * @throws InvalidArgumentException when the wiring of the grants does not hold together
     *
     * @return list<GrantTypeName>
     */
    public function grantTypes(ServedGrantsInterface $served): array;

    /**
     * @return non-empty-list<Hop>
     */
    public function hops(): array;
}
