<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use function array_map;
use Beffroi\Core\Domain\Algorithm\NamedAlgorithmInterface;

final readonly class AlgorithmNames
{
    /**
     * @param list<NamedAlgorithmInterface> $algorithms
     *
     * @return ($algorithms is non-empty-list<NamedAlgorithmInterface> ? non-empty-list<non-empty-string> : list<non-empty-string>)
     */
    public static function of(array $algorithms): array
    {
        return array_map(static fn (NamedAlgorithmInterface $algorithm): string => $algorithm->name(), $algorithms);
    }
}
