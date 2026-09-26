<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Consent;

use function array_map;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\ConsentRevoked;
use Heidi\Oidc\Domain\Token\RevokedTokenHashes;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\GrantsOfAConsentInterface;
use Heidi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * What a user taking back what they agreed to comes to (architecture §4.3), the counterpart of
 * ConsentGranting: the consent revoked, so that the next authorization request of that client asks
 * afresh, and what was issued under it taken out of use with it.
 *
 * Taking the consent alone back would leave the client calling the resources of this provider with the
 * tokens it already holds, which is not what a user saying "no longer" is asking for. So the grants that
 * user left to that client are revoked, which is what a resource of this provider asks of every token it
 * is presented (architecture §4.6); the refresh tokens are revoked, so that nothing renews; the opaque
 * access tokens are removed, and an unknown token is an invalid one (RFC 6750 §3.1). A self-contained
 * token in the hands of a resource server that verifies it offline lives to its expiry whatever is done
 * here (RFC 9068 §4), and its introspection says the truth about it from this instant.
 *
 * Recorded here whichever asked, the page of the account or the console: a consent taken back is the same
 * fact however it was asked for, as a consent granted is.
 */
final readonly class ConsentRevocation
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private AuthorizationCodeRepositoryInterface $codes,
        private GrantsOfAConsentInterface $grants,
        private RefreshTokenRevocation $refreshTokens,
        private RefreshTokensOfAConsentInterface $renewals,
        private CanRevokeAccessTokensByConsentInterface $accessTokens,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    public function revoke(Consent $consent, RequestContext $context): void
    {
        $now = $this->clock->now();
        $consent->revoke($now);
        $this->consents->save($consent);
        $grants = [];
        foreach ($this->grants->ofConsent($consent) as $code) {
            if ($code->isRevoked()) {
                continue;
            }
            $code->revoke($now);
            $this->codes->save($code);
            $grants[] = $code;
        }
        $refreshTokens = $this->refreshTokens->revokeAll($this->renewals->ofConsent($consent), $now);
        $accessTokens = $this->accessTokens->revokeByConsent($consent);
        $this->events->dispatch(new ConsentRevoked(
            $now,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $consent->user->id,
            array_map(static fn (AuthorizationCode $code): Uuid => $code->grantId, $grants),
            RevokedTokenHashes::of($refreshTokens),
            RevokedTokenHashes::of($accessTokens),
            $context,
        ));
    }
}
