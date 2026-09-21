<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Token\GrantInterface;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use function in_array;

/**
 * The discovery endpoint (OIDC Discovery §4, architecture §4.8): the issuer, the endpoints, what the claims
 * provider announces, the grants wired into the token endpoint (the same tagged grants TokenHandler
 * serves), the response modes the authorization endpoint answers in (the same ways of answering the
 * parser accepts), the client authentication methods it is wired with and the classes of
 * the policy of the tenant the wired logins can prove (decision 0010), the ways of telling a client that
 * a session ended the integration wires, the algorithms it signs its JWS with; "offline_access" when the
 * refresh token grant is served.
 * Everything else is fixed by the module.
 */
final readonly class DiscoveryHandler
{
    /**
     * @var non-empty-list<GrantType>
     */
    private array $grantTypes;

    /**
     * @param iterable<GrantInterface> $grants the grants of the token endpoint, at least one
     * @param int $maxAge how long a client may cache the document, in seconds
     */
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private MutualTlsEndpointLocatorInterface $mutualTlsEndpoints,
        private ClaimsProviderInterface $claims,
        private ProvableMethodsInterface $provable,
        private ServedResponseModesInterface $responseModes,
        private ClientAuthenticationMethodsInterface $clientAuthenticationMethods,
        private ServedLogoutChannelsInterface $logoutChannels,
        private SignatureAlgorithmsInterface $algorithms,
        iterable $grants,
        private int $maxAge = 3600,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
        $grantTypes = [];
        foreach ($grants as $grant) {
            $grantTypes[] = $grant->grantType();
        }
        if ($grantTypes === []) {
            throw new InvalidArgumentException('The token endpoint serves at least one grant.');
        }
        $this->grantTypes = $grantTypes;
    }

    public function handle(Tenant $tenant): ProviderMetadata
    {
        $scopes = $this->claims->supportedScopes();
        if (in_array(GrantType::RefreshToken, $this->grantTypes, true)) {
            $scopes[] = Scope::offlineAccess();
        }

        return new ProviderMetadata(
            $tenant->issuer,
            $this->endpoints->locate($tenant),
            $this->mutualTlsEndpoints->locateMutualTls($tenant),
            $scopes,
            $this->claims->supportedClaims(),
            $this->responseModes->servedResponseModes(),
            $this->grantTypes,
            $this->clientAuthenticationMethods->clientAuthenticationMethods(),
            array_map(
                static fn (AuthenticationContextClass $class): string => $class->value,
                $tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods()),
            ),
            $this->algorithms->all(),
            $this->logoutChannels->servedLogoutChannels(),
            $this->maxAge,
        );
    }
}
