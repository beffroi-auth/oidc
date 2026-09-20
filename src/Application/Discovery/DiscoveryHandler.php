<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\GrantInterface;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use function in_array;

/**
 * The discovery endpoint (OIDC Discovery §4, architecture §4.8): the issuer, the endpoints, what the claims
 * provider announces, the grants wired into the token endpoint (the same tagged grants TokenHandler
 * serves), the client authentication methods ClientAuthenticator implements and the classes of the policy
 * of the tenant the wired logins can prove (decision 0010); "offline_access" when the refresh token grant
 * is served. Everything else is fixed by the module.
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
        private ClaimsProviderInterface $claims,
        private ProvableMethodsInterface $provable,
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
            $scopes,
            $this->claims->supportedClaims(),
            $this->grantTypes,
            ClientAuthenticator::methods(),
            array_map(
                static fn (AuthenticationContextClass $class): string => $class->value,
                $tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods()),
            ),
            $this->maxAge,
        );
    }
}
