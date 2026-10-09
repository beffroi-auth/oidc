<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

/**
 * One exchange of a flow (issue #462): who sent it, who answered it, the name the specification gives
 * it, and the section that says so. One hop is one request or one response really made over the wire,
 * so that whatever draws a flow can show, beside the hop, the payload that travelled and nothing else.
 *
 * The name is the name of the exchange in the specification, not a sentence: it is read by the shape
 * that draws the hop and by whoever recorded one, and those two have to agree on it.
 */
final readonly class Hop
{
    /**
     * @param non-empty-string $name          the name the specification gives this exchange
     * @param non-empty-string $specification the RFC or the OpenID specification and its section
     * @param bool             $repeats       true when the same hop is made again until it is answered
     *                                        otherwise, as a client polling a token endpoint does
     */
    public function __construct(
        public Actor $from,
        public Actor $to,
        public string $name,
        public string $specification,
        public bool $repeats = false,
    ) {
    }
}
