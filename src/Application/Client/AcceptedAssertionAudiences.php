<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_any;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 7523 §3, FAPI 2.0 Security Profile §5.3.2.1, CIBA Core §7.1, RFC 8705 §5
 */
final readonly class AcceptedAssertionAudiences
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private MutualTlsEndpointLocatorInterface $mutualTlsEndpoints,
        private ServedGrantsInterface $grants,
    ) {
    }

    /**
     * @return non-empty-list<string> the issuer first
     */
    public function of(Tenant $tenant, Client $client): array
    {
        $registration = $client->registration;
        $asksThroughABackchannel = array_any(
            $this->grants->askingTheUserThroughABackchannel(),
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
        if (! $asksThroughABackchannel) {
            return [$tenant->issuer->value];
        }

        return [
            $tenant->issuer->value,
            ...self::endpointsOf($this->endpoints->locate($tenant)),
            ...self::endpointsOf($this->mutualTlsEndpoints->locateMutualTls($tenant)),
        ];
    }

    /**
     * CIBA Core §7.1
     *
     * @return list<string>
     */
    private static function endpointsOf(?ProviderEndpoints $endpoints): array
    {
        return $endpoints === null ? [] : [$endpoints->token, $endpoints->backchannelAuthentication];
    }
}
