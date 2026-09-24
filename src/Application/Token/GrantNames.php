<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_map;
use Heidi\Oidc\Domain\Client\GrantTypeName;

/**
 * The names of grant types, read from the names themselves. Every place that has to say them, the
 * discovery document, the panel of the profiler and the message a registration naming an unwired grant
 * is refused with, reads them here: a grant names itself and nothing writes that reading again.
 */
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
