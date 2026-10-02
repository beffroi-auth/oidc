<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;

/**
 * RFC 9396 §10 "authorization_details_types_supported": the types of authorization detail a client of this
 * provider may name in an "authorization_details" parameter (§2), which are the ones wired into it and not
 * an enumeration kept beside them (issue #98). A type names itself, so a type the provider gains is
 * announced by the fact of being served.
 *
 * A deployment wired with none announces nothing: the member would be an empty list, which a client would
 * read as "no type is acceptable here" rather than as "this provider serves no rich authorization request",
 * and §10 makes the member optional for exactly that case.
 */
final readonly class AnnouncedAuthorizationDetails implements MetadataContributorInterface
{
    public function __construct(
        private ServedAuthorizationDetailTypesInterface $types,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $types = $this->types->servedAuthorizationDetailTypes();
        if ($types === []) {
            return [];
        }

        return [
            'authorization_details_types_supported' => $types,
        ];
    }
}
