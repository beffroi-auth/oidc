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
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * CIBA Core §10.1, §11
 *
 * "slow_down" is said only of a pending request: a client called back (§10.2) is answered as soon as it asks.
 * What the KMS opens is read before the record is spent, so a KMS that does not answer leaves it to the next poll.
 */
final readonly class BackchannelAuthenticationGrant implements AsksTheUserThroughABackchannelInterface, IssuesRefreshTokensInterface
{
    public const string GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

    private const string INVALID = 'The auth_req_id is invalid.';

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
        if ($record->isDenied()) {
            throw new AccessDeniedException('The end user denied the request.', false);
        }
        if ($record->isRevoked()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if (! $record->isApproved()) {
            // CIBA Core §11: every poll is saved, the refused ones included, so asking again buys no faster answer.
            $tooSoon = $record->polledTooSoon($now);
            $this->records->save($record);
            if ($tooSoon) {
                throw new SlowDownException('The client is polling faster than the interval it was given, which grows by five seconds (CIBA Core section 11).');
            }

            throw new AuthorizationPendingException('The end user has not answered the request yet (CIBA Core section 11).');
        }
        $addressed = $this->issuer->address($record->client, $record->scopes);
        $session = $record->session;
        $authentication = $record->authentication;
        $granted = $session !== null && $authentication !== null && $session->isActive($now);
        // Atomic: of the requests presenting this auth_req_id at once, exactly one is the first.
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
                $record->authRequestIdHash,
                $authorization->grantId,
                $now,
                $now->add($this->refreshTokenFamilyLifetime),
            );
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now, $addressed);
    }
}
