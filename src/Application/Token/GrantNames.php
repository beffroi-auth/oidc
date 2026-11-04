<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_map;
use Beffroi\Oidc\Domain\Client\GrantTypeName;

final readonly class GrantNames
{
    /**
     * @param list<GrantTypeName> $grantTypes
     *
     * @return list<string>
     */
    public static function of(array $grantTypes): array
    {
        return array_map(static fn (GrantTypeName $grantType): string => $grantType->value, $grantTypes);
    }
}
