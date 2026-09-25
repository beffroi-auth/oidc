<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\UuidGeneratorInterface;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\AuthorizationPendingException;
use Heidi\Oidc\Exception\ExpiredTokenException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\SlowDownException;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
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
 * to somebody else or expired is beyond polling, polling too fast is answered before anything is read of
 * the user's answer, and only then does the answer itself count.
 *
 * What comes out is an authorization of the ordinary kind, descending from the session the user approved
 * with: the same scopes, the same consent, the same session rules, so the tokens are the ones of a code
 * and nothing new. They are bound to what this request proved and not to what the approval proved
 * (RFC 8705 §3, RFC 9449 §5): the browser that approved holds nothing the appliance can prove.
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
        // RFC 8628 §3.5: the poll is recorded whatever comes of it, so the record is saved on every path
        // out of here and not only on the one that grants
        $tooSoon = $record->polledTooSoon($now);
        $this->records->save($record);
        if ($tooSoon) {
            throw new SlowDownException('The client is polling faster than the interval it was given, which grows by five seconds (RFC 8628 section 3.5).');
        }
        if ($record->isDenied()) {
            throw new AccessDeniedException('The end user denied the request.', false);
        }
        if (! $record->isApproved()) {
            throw new AuthorizationPendingException('The end user has not answered the request yet (RFC 8628 section 3.5).');
        }
        // atomic: of the requests presenting this device code at once, exactly one is the first
        if (! $this->records->consume($record, $now)) {
            throw new InvalidGrantException(self::INVALID);
        }
        $session = $record->session;
        $authentication = $record->authentication;
        if ($session === null || $authentication === null || ! $session->isActive($now)) {
            throw new InvalidGrantException(self::INVALID);
        }

        $authorization = new UserAuthorization(
            $this->grantType(),
            $this->uuids->timeOrdered(),
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
                $record->deviceCodeHash,
                $authorization->grantId,
                $now,
                $now->add($this->refreshTokenFamilyLifetime),
            );
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now);
    }
}
