<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateInterval;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\AuthorizationPendingException;
use Beffroi\Oidc\Exception\ExpiredTokenException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\SlowDownException;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * RFC 8628 §3.4, §3.5 (architecture §4.5): the client that has no browser polls for the answer somebody
 * gave elsewhere. This is the one grant of the provider that answers "not yet": "authorization_pending"
 * while the user has not answered, "slow_down" when the client asks faster than it was told to,
 * "expired_token" once the code is past its lifetime, "access_denied" when the user said no.
 *
 * What it spends is a record read once, as the authorization code grant spends a code: of any number of
 * requests presenting one device code at once exactly one is served, and a code presented again is worth
 * nothing. The order of the answers is the order of what a client can do about them: a code that belongs
 * to somebody else or expired is beyond polling, then the answer the user gave, and the interval bounds
 * the wait and only the wait. "slow_down" is a variant of "authorization_pending" (§3.5), so it is
 * something to say about a request that is still pending and nothing to say about one that is over: a
 * request that has an answer is answered, however soon after the last one it is asked for.
 *
 * What the response reads from outside the provider is read before the record is spent (architecture
 * §4.5): the keys of the tenant its tokens are signed with, opened by the KMS, the key the ID token is
 * encrypted to (OIDC Core §3.1.3.7), and the session the user approved with, which a store reads with the
 * person it names and opens under the data keys of the tenant (decision 0018). A KMS that does not answer,
 * or keys the client cannot serve right now, leave the device code to its next poll.
 *
 * What comes out is an authorization of the ordinary kind, descending from the session the user approved
 * with: the same scopes, the same consent, the same session rules, so the tokens are the ones of a code
 * and nothing new. They are bound to what this request proved and not to what the approval proved
 * (RFC 8705 §3, RFC 9449 §5): the browser that approved holds nothing the appliance can prove.
 *
 * The grant those tokens name is the record's own and is not drawn here (GrantRecord): a resource of this
 * provider asks of every token whether the grant behind it is still alive, and the answer is a row.
 */
final readonly class DeviceCodeGrant implements AsksTheUserOnAnotherDeviceInterface, IssuesRefreshTokensInterface
{
    private const string INVALID = 'The device code is invalid.';

    /**
     * @param DateInterval $refreshTokenFamilyLifetime the absolute lifetime no rotation extends (architecture §4.6)
     */
    public function __construct(
        private DeviceAuthorizationRecordRepositoryInterface $records,
        private TokenIssuer $issuer,
        private RefreshTokenDue $refreshTokenDue,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
        private DateInterval $refreshTokenFamilyLifetime = new DateInterval('P90D'),
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName('urn:ietf:params:oauth:grant-type:device_code');
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $record = $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($request->required('device_code')));
        if ($record === null || ! $record->belongsTo($client->client)) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($record->isExpired($now)) {
            throw new ExpiredTokenException('The device code has expired and the client starts a new request (RFC 8628 section 3.5).');
        }
        if ($record->isDenied()) {
            throw new AccessDeniedException('The end user denied the request.', false);
        }
        if (! $record->isApproved()) {
            // RFC 8628 §3.5: every poll is recorded, the refused ones included, so that asking again does
            // not buy a faster answer; the record is saved before either of the two answers below
            $tooSoon = $record->polledTooSoon($now);
            $this->records->save($record);
            if ($tooSoon) {
                throw new SlowDownException('The client is polling faster than the interval it was given, which grows by five seconds (RFC 8628 section 3.5).');
            }

            throw new AuthorizationPendingException('The end user has not answered the request yet (RFC 8628 section 3.5).');
        }
        $addressed = $this->issuer->address($record->client, $record->scopes);
        $session = $record->session;
        $authentication = $record->authentication;
        $granted = $session !== null && $authentication !== null && $session->isActive($now);
        // atomic: of the requests presenting this device code at once, exactly one is the first
        if (! $this->records->consume($record, $now)) {
            throw new InvalidGrantException(self::INVALID);
        }
        if (! $granted) {
            throw new InvalidGrantException(self::INVALID);
        }

        $authorization = new UserAuthorization(
            $this->grantType(),
            $record->grantId,
            $record->client,
            $session,
            $record->scopes,
            $record->scopes,
            null,
            null,
            $authentication,
            $client->confirmation,
            $record->resources,
            $record->resources,
        );
        $refreshToken = null;
        if ($this->refreshTokenDue->forThe($authorization)) {
            $family = new RefreshTokenFamily(
                $this->uuids->timeOrdered(),
                $authorization->tenant,
                $record->deviceCodeHash,
                $authorization->grantId,
                $now,
                $now->add($this->refreshTokenFamilyLifetime),
            );
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now, $addressed);
    }
}
