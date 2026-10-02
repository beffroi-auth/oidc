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
 * A client that registers itself gets nothing a declared client does not get (decision 0009). Most of
 * that rule is already where a registration meets the wiring: the grants, the authentication methods,
 * the access token shapes, the signature algorithms, the delivery modes and the kinds of "sub" a client
 * may name are the ones the provider is wired with, and the one reader of a registration refuses a name
 * outside them whoever wrote it.
 *
 * What is left is what a tenant has and the wiring has not: the scopes it hands out tokens for, which
 * are the ones it announces (`OfferedScopes`). A registration that names another is refused rather than
 * granted, and the document is what it is held to, so that a client cannot write into the document by
 * registering a scope nothing serves.
 *
 * It is read here for a registration the provider is about to write, the creation of RFC 7591 §3.1 and
 * the replacement of RFC 7592 §2.2: a declaration is read at a boot that has no tenant instance, and
 * what a tenant offers is what its own clients have made of it.
 */
final readonly class RegistrationHeldToTheTenant
{
    public function __construct(
        private OfferedScopesInterface $scopes,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException when the registration names something the tenant does not offer
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
