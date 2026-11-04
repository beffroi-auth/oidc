<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

final readonly class GrantTypesApart
{
    /**
     * @param list<GrantTypeName> $all
     * @param list<GrantTypeName> $without
     *
     * @return list<GrantTypeName> in the order of the first list
     */
    public static function of(array $all, array $without): array
    {
        $apart = [];
        foreach ($all as $grantType) {
            foreach ($without as $excluded) {
                if ($excluded->equals($grantType)) {
                    continue 2;
                }
            }
            $apart[] = $grantType;
        }

        return $apart;
    }
}
