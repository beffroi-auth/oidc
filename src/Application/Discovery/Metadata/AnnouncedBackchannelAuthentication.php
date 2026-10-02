<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Ciba\DeliveryModeNames;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedDeliveryModesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * CIBA Core §4: where a client starts a request for a user it names, and the ways it may be told that
 * the request has been answered. Both are read from what the provider is wired with, the modes being
 * one class each; the grant that goes with them is announced by the fact of being wired, as every other
 * is (AnnouncedGrants).
 *
 * A provider wired with no grant of this flow announces none of it, rather than an endpoint nothing
 * serves. The algorithms are the ones the provider verifies a signature with, this endpoint reading a
 * signed request exactly as the pushed one does (RFC 9101 §6.1). "user_code" is a secret of the user
 * this provider does not take, and the document says so rather than leaving a client to find out.
 */
final readonly class AnnouncedBackchannelAuthentication implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
        private ServedDeliveryModesInterface $modes,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        if ($this->grants->askingTheUserThroughABackchannel() === []) {
            return [];
        }

        return [
            'backchannel_authentication_endpoint' => $this->endpoints->locate($tenant)->backchannelAuthentication,
            'backchannel_token_delivery_modes_supported' => DeliveryModeNames::of($this->modes->servedDeliveryModes()),
            'backchannel_authentication_request_signing_alg_values_supported' => $this->algorithms->signing(),
            'backchannel_user_code_parameter_supported' => false,
        ];
    }
}
