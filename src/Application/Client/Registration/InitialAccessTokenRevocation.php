<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A tenant takes back what it handed out (RFC 7591 §1.2, decision 0009): the token authorises nothing
 * from that instant, whatever it was still worth and whenever it would have expired.
 *
 * It is taken back by its identifier and never by its value, because the tenant does not hold the value
 * and the row holds only a digest. Revoking one twice is revoking it once: the instant kept is the first,
 * so that what a record says happened is what happened.
 *
 * Nothing is done to the clients that token already registered. They exist, they were registered under an
 * authorisation that held at the time, and a client is taken back by taking that client back
 * (`RegisteredClientRemoval`); a token worth ten that registered three is not three deletions waiting.
 */
final readonly class InitialAccessTokenRevocation
{
    public function __construct(
        private IssuedInitialAccessTokensInterface $issued,
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @return InitialAccessToken|null the token as it now stands, null when that tenant has no token of
     *                                 that identifier
     */
    public function revoke(Tenant $tenant, Uuid $id): ?InitialAccessToken
    {
        $token = $this->issued->find($tenant, $id);
        if ($token === null) {
            return null;
        }
        $token->revoke($this->clock->now());
        $this->tokens->save($token);

        return $token;
    }
}
