<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Port\SubjectsOfSessionsInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Domain\Token\RevokedTokenHashes;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;

/**
 * RFC 6749 §4.1.3, RFC 7636 §4.6, OIDC Core §3.1.3
 *
 * What the KMS opens is read before the code is consumed: a code consumed and left unanswered would make its next
 * presentation a replay.
 */
final readonly class AuthorizationCodeGrant implements IssuesRefreshTokensInterface, SendsTheUserToTheClientInterface
{
    private const string INVALID = 'The authorization code is invalid.';

    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private RefreshTokenRevocation $refreshTokens,
        private AccessTokenRepositoryInterface $accessTokens,
        private SubjectsOfSessionsInterface $subjects,
        private TokenIssuer $issuer,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private RefreshTokenDue $refreshTokenDue,
        private RequestedAuthorizationDetails $authorizationDetails,
        private DateInterval $refreshTokenFamilyLifetime = new DateInterval('P90D'),
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName('authorization_code');
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $code = $request->required('code');
        $redirectUri = $request->required('redirect_uri');
        $codeVerifier = $request->optional('code_verifier');
        if ($codeVerifier !== null && ! CodeChallenge::hasTheShape($codeVerifier)) {
            throw new InvalidRequestException('The code_verifier parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.1).');
        }

        $record = $this->codes->findByCodeHash(DrawnSecret::digestOf($code));
        if ($record === null) {
            throw new InvalidGrantException(self::INVALID);
        }
        $addressed = $record->isUsed() ? null : $this->issuer->address($record->client, $record->scopes);
        $sessionActive = ! $record->isUsed() && $record->session->isActive($now);
        // Atomic: of the requests presenting this code at once, exactly one is the first.
        if (! $this->codes->consume($record, $now)) {
            $this->replayed($record, $client->client, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }

        if (
            ! $record->client->equals($client->client)
            || $record->isExpired($now)
            || ! $record->redirectUri->matches($redirectUri)
            || ! self::pkceSatisfied($record, $codeVerifier)
            || ! self::reservationSatisfied($record, $client)
            || ! $sessionActive
        ) {
            throw new InvalidGrantException(self::INVALID);
        }

        $authorization = UserAuthorization::fromAuthorizationCode(
            $this->grantType(),
            $record,
            $client->confirmation,
            RequestedResources::of($request, $record->resources),
            $this->authorizationDetails->of($request, $record->authorizationDetails),
        );
        $refreshToken = null;
        if ($this->refreshTokenDue->forThe($authorization)) {
            $family = new RefreshTokenFamily(
                $this->uuids->timeOrdered(),
                $authorization->tenant,
                $record->codeHash,
                $record->grantId,
                $now,
                $now->add($this->refreshTokenFamilyLifetime),
            );
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now, $addressed);
    }

    /**
     * RFC 7636 §4.6 when the code carries a challenge, RFC 9700 §4.8.2 when it carries none.
     */
    private static function pkceSatisfied(AuthorizationCode $record, #[SensitiveParameter] ?string $codeVerifier): bool
    {
        if ($record->codeChallenge === null) {
            return $codeVerifier === null;
        }

        return $codeVerifier !== null && $record->codeChallenge->verifies($codeVerifier);
    }

    /**
     * RFC 9449 §10.1
     */
    private static function reservationSatisfied(AuthorizationCode $record, AuthenticatedClient $client): bool
    {
        return $record->dpopKey === null || $client->confirmation !== null && $client->confirmation->matches($record->dpopKey);
    }

    /**
     * RFC 6749 §4.1.2
     *
     * The person is named by the subject the store of sessions keeps in the clear, so the KMS need not answer.
     */
    private function replayed(AuthorizationCode $code, Client $presentedBy, RequestContext $context, DateTimeImmutable $now): void
    {
        $code->revoke($now);
        $this->codes->save($code);
        $revoked = $this->refreshTokens->revokeByAuthorizationCode($code->codeHash, $now);
        if ($this->accessTokens instanceof CanRevokeAccessTokensByGrantInterface) {
            $this->accessTokens->revokeByGrant($code->grantId);
        }
        $this->events->dispatch(new AuthorizationCodeReplayed(
            $now,
            $code->tenant,
            $code->codeHash,
            $this->subjects->of($code->session->id),
            $code->clientId,
            $presentedBy->registration->clientId,
            RevokedTokenHashes::of($revoked),
            $context,
        ));
    }
}
