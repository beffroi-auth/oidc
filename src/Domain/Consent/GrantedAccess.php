<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Consent;

use function array_map;
use Beffroi\Oidc\Domain\Scope\Scope;
use function in_array;
use function sort;
use const SORT_STRING;

/**
 * What a set of consents grants, each scope, claim and type of authorization details once, in the order of
 * their names: what a list of consents can be narrowed to (ConsentQuestion).
 */
final readonly class GrantedAccess
{
    /**
     * @param list<Scope> $scopes
     * @param list<string> $claims
     * @param list<string> $types RFC 9396 §2
     */
    private function __construct(
        public array $scopes,
        public array $claims,
        public array $types,
    ) {
    }

    /**
     * @param list<Consent> $consents
     */
    public static function of(array $consents): self
    {
        $scopes = [];
        $claims = [];
        $types = [];
        foreach ($consents as $consent) {
            foreach ($consent->scopes as $scope) {
                $scopes = self::with($scopes, $scope->value);
            }
            foreach ($consent->claims as $claim) {
                $claims = self::with($claims, $claim);
            }
            foreach ($consent->authorizationDetails?->types() ?? [] as $type) {
                $types = self::with($types, $type);
            }
        }

        return new self(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes), $claims, $types);
    }

    /**
     * @param list<string> $names
     *
     * @return list<string> in the order of the names, each once
     */
    private static function with(array $names, string $name): array
    {
        if (! in_array($name, $names, true)) {
            $names[] = $name;
            sort($names, SORT_STRING);
        }

        return $names;
    }
}
