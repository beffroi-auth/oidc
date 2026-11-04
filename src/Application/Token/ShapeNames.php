<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_map;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

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
