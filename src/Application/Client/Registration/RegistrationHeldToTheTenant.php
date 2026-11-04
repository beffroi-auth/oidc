<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function array_any;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Port\OfferedScopesInterface;
use function sprintf;

/**
 * Refuses a registration that names a scope its tenant does not offer.
 */
final readonly class RegistrationHeldToTheTenant
{
    public function __construct(
        private OfferedScopesInterface $scopes,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException
     */
    public function assertHolds(Tenant $tenant, ClientRegistration $registration, ClientMetadata $metadata): void
    {
        $offered = $this->scopes->scopesOfferedIn($tenant);
        foreach ($registration->allowedScopes as $scope) {
            if (! array_any($offered, static fn (Scope $held): bool => $held->equals($scope))) {
                throw new InvalidClientMetadataException(
                    'scope',
                    $metadata->has('scope') ? $metadata->sourceOf('scope') : null,
                    sprintf(
                        'The client "%s" registers the scope "%s", which this tenant does not hand out tokens for (decision 0009).',
                        $registration->clientId,
                        $scope,
                    ),
                );
            }
        }
    }
}
