<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use function array_map;
use Beffroi\Core\Domain\Algorithm\NamedAlgorithmInterface;

/**
 * The names of the algorithms the provider is wired with, whatever they are wired for. Every place that
 * has to say them, the discovery document, a method that decides what it verifies a signature under, and
 * the message a registration is refused with, reads them here: an algorithm names itself and nothing
 * writes that reading again.
 */
final readonly class AlgorithmNames
{
    /**
     * @param list<NamedAlgorithmInterface> $algorithms as a registry of the wiring hands them over, in the order they are wired
     *
     * @return ($algorithms is non-empty-list<NamedAlgorithmInterface> ? non-empty-list<non-empty-string> : list<non-empty-string>)
     */
    public static function of(array $algorithms): array
    {
        return array_map(static fn (NamedAlgorithmInterface $algorithm): string => $algorithm->name(), $algorithms);
    }
}
