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
 * CIBA Core §4
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
