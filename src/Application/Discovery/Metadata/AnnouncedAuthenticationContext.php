<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\SubjectType;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;

/**
 * OIDC Discovery §3 and decision 0010: the classes of the tenant's policy that its wired logins can
 * actually satisfy, in the order the policy names them, and the kinds of "sub" this provider assigns one
 * for, read where a registration reads them (SubjectType).
 */
final readonly class AnnouncedAuthenticationContext implements MetadataContributorInterface
{
    public function __construct(
        private ProvableMethodsInterface $provable,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $classes = $tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods());

        return [
            'acr_values_supported' => array_map(
                static fn (AuthenticationContextClass $class): string => $class->value,
                $classes,
            ),
            'subject_types_supported' => array_map(
                static fn (SubjectType $type): string => $type->value,
                SubjectType::assigned(),
            ),
        ];
    }
}
