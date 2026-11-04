<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Consent;

use function array_map;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Domain\Token\RevokedTokenHashes;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Also revokes what was issued under the consent; a token verified offline still lives to its expiry.
 */
final readonly class ConsentRevocation
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private CanRevokeGrantsByConsentInterface $grants,
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
        $grants = $this->grants->revokeByConsent($consent, $now);
        $refreshTokens = $this->refreshTokens->revokeAll($this->renewals->ofConsent($consent), $now);
        $accessTokens = $this->accessTokens->revokeByConsent($consent);
        $this->events->dispatch(new ConsentRevoked(
            $now,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $consent->user->subject,
            array_map(static fn (GrantRecord $grant): Uuid => $grant->grantId, $grants),
            RevokedTokenHashes::of($refreshTokens),
            RevokedTokenHashes::of($accessTokens),
            $context,
        ));
    }
}
