<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_any;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * Whether a response carries a refresh token beside its access token (RFC 6749 §4.1.4, OIDC Core §11). Every
 * grant that may issue one asks the same three questions of the authorization it spends, so they are asked
 * here once rather than in each of them: a refresh token this client could not spend is one no response
 * carries, "offline_access" asks for one, and a confidential client gets one without asking unless the
 * deployment says otherwise.
 *
 * What spends a refresh token is what the provider is wired with and what the client registered for, and
 * neither the grant that issues one nor the client names it.
 */
final readonly class RefreshTokenDue
{
    /**
     * @param ServedGrantsInterface $servedGrants what the provider serves, read for the grants that spend a refresh token
     * @param bool $withoutOfflineAccess whether a confidential client gets one without asking for "offline_access"
     */
    public function __construct(
        private ServedGrantsInterface $servedGrants,
        private bool $withoutOfflineAccess = true,
    ) {
    }

    public function forThe(UserAuthorizationInterface $authorization): bool
    {
        $registration = $authorization->client->registration;
        $spent = array_any(
            $this->servedGrants->spendingRefreshTokens(),
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
        if (! $spent) {
            return false;
        }
        if ($authorization->scopes->has(Scope::offlineAccess())) {
            return true;
        }

        return $this->withoutOfflineAccess && ! $registration->isPublic();
    }
}
