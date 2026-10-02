<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_map;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

/**
 * The names of the shapes an access token is written in, read from the shapes themselves. Every place
 * that has to say them, the panel of the profiler and the message a registration naming an unwired
 * shape is refused with, reads them here: a shape names itself and nothing writes that reading again.
 */
final readonly class ShapeNames
{
    /**
     * @param list<AccessTokenShapeInterface> $shapes
     *
     * @return ($shapes is non-empty-list<AccessTokenShapeInterface> ? non-empty-list<non-empty-string> : list<non-empty-string>)
     */
    public static function of(array $shapes): array
    {
        return array_map(static fn (AccessTokenShapeInterface $shape): string => $shape->name(), $shapes);
    }
}
