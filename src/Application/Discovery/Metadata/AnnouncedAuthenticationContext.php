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
 * OIDC Discovery §3 and decision 0010: the classes of the tenant's policy that its wired logins can
 * actually satisfy, in the order the policy names them, and the kinds of "sub" this provider assigns one
 * of, read from what resolves them and never named here.
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
        $classes = $tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods());

        return [
            'acr_values_supported' => array_map(
                static fn (AuthenticationContextClass $class): string => $class->value,
                $classes,
            ),
            'subject_types_supported' => $this->subjects->assignedSubjectTypes(),
        ];
    }
}
