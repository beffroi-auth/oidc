<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use DateTimeImmutable;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * What was issued under a session taken out of use when that session ends (architecture §4.9, decision
 * 0006): every refresh token of the session revoked, rotated ones included, and every opaque access token of
 * the session removed, an unknown token being an invalid one (RFC 6750 §3.1). Whatever ended it, the user
 * at the end session endpoint, a relying party, a service provider of SAML, the page of the account, the
 * console or a sign-in that replaced it, since it is made on the end and not on the request that asked for
 * it, as the back-channel logout is: no caller of SessionTerminator has it to remember (issue #741).
 *
 * **It is dated by the end, not by its own run.** A token stopped being usable at the instant its session
 * ended, so that is the date its revocation carries, however long the queue held the event.
 *
 * **It waits for the queue, because nothing waits for it.** What refuses a token the next request presents
 * is the session, which SessionTerminator writes as ended before the event leaves: a resource of the
 * provider refuses a token whose session has ended (AccessTokenInspector), and the token endpoint a refresh
 * token whose session has ended (RefreshTokenGrant), both reading the session and neither the token's own
 * state. So the revocation writes down what is already true and can wait for the lane of the events
 * (architecture §5.6); nothing is added to the writes that are synchronous.
 *
 * **A token saved after it ran is revoked at its first use.** A refresh that read the session as active
 * before SessionTerminator wrote it ended, and saved its rotated successor after this ran, leaves that
 * successor recorded active. The window is the record's only, the token being refused at its use as every
 * token of an ended session is, and it closes at that first use: the token endpoint announces
 * RefreshTokenOutlivedItsSession as it refuses it, and this runs again on that event, dated by the same end.
 * No lock is taken for it.
 *
 * **A self-contained access token keeps what it says.** The provider keeps no list of the "at+jwt" it
 * revoked (RFC 7009 §2.2.1): a resource server that verifies one offline accepts it to its expiry whatever is
 * done here (RFC 9068 §4), and only its introspection, and the provider's own resources, refuse it from the
 * end of the session, by the "sid" it carries. A token a client holds for itself descends from no session
 * and is not reached.
 */
final readonly class SessionTokensRevocation
{
    public function __construct(
        private RefreshTokenRevocation $refreshTokens,
        private CanRevokeAccessTokensBySessionInterface $accessTokens,
    ) {
    }

    public function sessionEnded(Uuid $session, DateTimeImmutable $endedAt): void
    {
        $this->refreshTokens->revokeBySession($session, $endedAt);
        $this->accessTokens->revokeBySession($session);
    }
}
