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
 * The names of this provider a client assertion may name in its "aud" (RFC 7523 §3, "a value that
 * identifies the authorization server as an intended audience").
 *
 * The issuer identifier of the tenant is what every client may name, and the only thing: FAPI 2.0
 * Security Profile §5.3.2.1 clause 8 lets an authorization server accept that one value and no other,
 * although RFC 7523 §3 permits the URL of the token endpoint and OIDC Core §9 recommends it.
 *
 * A client registered for a grant whose user this provider reaches itself may also name the URL of the
 * token endpoint or of the backchannel authentication endpoint: CIBA Core §7.1 names the ambiguity over
 * which audience such a client writes and settles it by making the provider accept all three. The
 * exception is the client's and is read from what it registered, never from an option (decision 0016,
 * under decision 0006): the strict rule and the interoperable one therefore live on one tenant, and a
 * client that never asks for a user on the back channel is held to the issuer alone.
 *
 * Both hosts of an endpoint are names of it, the ordinary one and the one whose TLS listener asks for a
 * certificate (RFC 8705 §5), because that is where a client presenting one reaches it.
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
     * @return non-empty-list<string> the issuer first, whatever the client registered
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
     * The two endpoints CIBA Core §7.1 names beside the issuer: the one such a request is sent to and the
     * one its answer is collected from.
     *
     * @param ProviderEndpoints|null $endpoints null when the deployment serves no host that asks for a certificate
     *
     * @return list<string>
     */
    private static function endpointsOf(?ProviderEndpoints $endpoints): array
    {
        return $endpoints === null ? [] : [$endpoints->token, $endpoints->backchannelAuthentication];
    }
}
