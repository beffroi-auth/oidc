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
 * RFC 8628 §3.4, §3.5
 *
 * What the KMS opens is read before the record is spent, so a KMS that does not answer leaves it to the next poll.
 */
final readonly class DeviceCodeGrant implements AsksTheUserOnAnotherDeviceInterface, IssuesRefreshTokensInterface
{
    private const string INVALID = 'The device code is invalid.';

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
            // RFC 8628 §3.5: every poll is saved, the refused ones included, so asking again buys no faster answer.
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
        // Atomic: of the requests presenting this device code at once, exactly one is the first.
        if (! $this->records->consume($record, $now)) {
            throw new InvalidGrantException(self::INVALID);
        }
        if (! $granted || $record->isRevoked()) {
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
