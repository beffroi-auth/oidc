<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_any;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 6749 §4.1.4, OIDC Core §11
 */
final readonly class RefreshTokenDue
{
    /**
     * @param bool $withoutOfflineAccess whether a confidential client gets a refresh token without "offline_access"
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
