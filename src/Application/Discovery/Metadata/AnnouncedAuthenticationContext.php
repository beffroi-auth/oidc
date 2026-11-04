<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ProvableMethodsInterface;

/**
 * OIDC Discovery §3
 */
final readonly class AnnouncedAuthenticationContext implements MetadataContributorInterface
{
    public function __construct(
        private ProvableMethodsInterface $provable,
        private AssignedSubjectTypesInterface $subjects,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $classes = $tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods($tenant));

        return [
            'acr_values_supported' => array_map(
                static fn (AuthenticationContextClass $class): string => $class->value,
                $classes,
            ),
            'subject_types_supported' => $this->subjects->assignedSubjectTypes(),
        ];
    }
}
