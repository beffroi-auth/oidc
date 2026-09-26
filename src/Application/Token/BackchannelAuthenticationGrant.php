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
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * CIBA Core §10.1, §11 (architecture §4.5): the client comes back for the answer its user gave on a
 * device of their own. It answers "not yet" as the device grant does, and for the same reasons:
 * "authorization_pending" while the user has not answered, "slow_down" when the client asks faster than
 * it was told to, "expired_token" once the request is past its lifetime, "access_denied" when the user
 * said no. A client that registered to be called back comes here too, once it has been told: the token
 * endpoint is the only place this provider hands a token out (§10.3 is not served, decision 0006).
 *
 * What it spends is a record read once, as the authorization code grant spends a code: of any number of
 * requests presenting one auth_req_id at once exactly one is served, and an identifier presented again is
 * worth nothing. The order of the answers is the order of what a client can do about them: an identifier
 * that belongs to somebody else or expired is beyond polling, polling too fast is answered before
 * anything is read of the user's answer, and only then does the answer itself count.
 *
 * What comes out is an authorization of the ordinary kind, descending from the session the user approved
 * with: the same scopes, the same consent, the same session rules, and an ID token, "openid" being
 * required of every request of this flow (§7.1). The tokens are bound to what this request proved and
 * not to what the approval proved (RFC 8705 §3, RFC 9449 §5): the browser that approved holds nothing
 * the client can prove.
 *
 * The grant those tokens name is the record's own and is not drawn here (GrantRecord): a resource of this
 * provider asks of every token whether the grant behind it is still alive, and the answer is a row.
 */
final readonly class BackchannelAuthenticationGrant implements AsksTheUserThroughABackchannelInterface, IssuesRefreshTokensInterface
{
    /**
     * CIBA Core §7.3, registered in the IANA "OAuth URI" registry.
     */
    public const string GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

    private const string INVALID = 'The auth_req_id is invalid.';

    /**
     * @param DateInterval $refreshTokenFamilyLifetime the absolute lifetime no rotation extends (architecture §4.6)
     */
    public function __construct(
        private BackchannelAuthenticationRecordRepositoryInterface $records,
        private TokenIssuer $issuer,
        private RefreshTokenDue $refreshTokenDue,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
        private DateInterval $refreshTokenFamilyLifetime = new DateInterval('P90D'),
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName(self::GRANT_TYPE);
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($request->required('auth_req_id')));
        if ($record === null || ! $record->belongsTo($client->client)) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($record->isExpired($now)) {
            throw new ExpiredTokenException('The auth_req_id has expired and the client starts a new request (CIBA Core section 11).');
        }
        // CIBA Core §11: the poll is recorded whatever comes of it, so the record is saved on every path
        // out of here and not only on the one that grants
        $tooSoon = $record->polledTooSoon($now);
        $this->records->save($record);
        if ($tooSoon) {
            throw new SlowDownException('The client is polling faster than the interval it was given, which grows by five seconds (CIBA Core section 11).');
        }
        if ($record->isDenied()) {
            throw new AccessDeniedException('The end user denied the request.', false);
        }
        if (! $record->isApproved()) {
            throw new AuthorizationPendingException('The end user has not answered the request yet (CIBA Core section 11).');
        }
        // atomic: of the requests presenting this auth_req_id at once, exactly one is the first
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
                $record->authRequestIdHash,
                $authorization->grantId,
                $now,
                $now->add($this->refreshTokenFamilyLifetime),
            );
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now);
    }
}
