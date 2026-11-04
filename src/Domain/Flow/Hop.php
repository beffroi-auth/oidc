<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

/**
 * One request or one response of a flow, named as its specification names it.
 */
final readonly class Hop
{
    /**
     * @param non-empty-string $name
     * @param non-empty-string $specification
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
