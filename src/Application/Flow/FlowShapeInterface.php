<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * One shape a flow of this provider has (issue #462): the hops it is made of, and which of the wired
 * grants have that shape, read from the capabilities those grants declare and from nothing else.
 *
 * A shape is wired as an opening or as a closing. A grant has exactly one opening, the way its flow
 * reaches a token, and as many closings as it has capabilities for what is done with that token; the
 * picture is the opening followed by the closings, in the order the wiring gives them. A flow the
 * provider gains is a shape added to the wiring, and a grant unwired takes its picture away with it.
 */
interface FlowShapeInterface
{
    /**
     * @throws InvalidArgumentException when the wiring of the grants does not hold together
     *
     * @return list<GrantTypeName> among the wired ones, those whose flow this shape draws
     */
    public function grantTypes(ServedGrantsInterface $served): array;

    /**
     * @return non-empty-list<Hop>
     */
    public function hops(): array;
}
