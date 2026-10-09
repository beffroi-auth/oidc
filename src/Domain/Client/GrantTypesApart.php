<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * The grant types of one list that are not in another, compared by name as a grant type always is. What
 * reads it is a reading of the wiring made of what the wiring does not say: the flow of a grant that
 * asks nobody anything, the closing a flow with nobody signed in behind it does not have.
 */
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
