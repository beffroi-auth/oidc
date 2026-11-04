<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Port\UuidGeneratorInterface;
use function array_keys;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Port\SigningKeyOpenerInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\CarriedAuthorizationDetails;
use Beffroi\Oidc\Domain\Token\ClientSubject;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\NamesItsSubjectInterface;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierOpenerInterface;

/**
 * RFC 9068 §2.1, §2.2, §2.2.1
 *
 * Signed in the provider's default algorithm, never the client's ID token one: resource servers read it.
 */
final readonly class JwtAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public const string TYPE = 'at+jwt';

    public const string USERINFO_CLAIMS = 'userinfo_claims';

    public const string GRANT_ID = 'grant_id';

    public const string PERSON = 'person';

    /**
     * RFC 8693 §4.1
     */
    public const string ACTOR = 'act';

    /**
     * RFC 8693 §4.4
     */
    public const string MAY_ACT = 'may_act';

    /**
     * RFC 9396 §7
     */
    public const string AUTHORIZATION_DETAILS = 'authorization_details';

    public function __construct(
        private SigningKeyOpenerInterface $signer,
        private SubjectIdentifierOpenerInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        private UuidGeneratorInterface $uuids,
        private SealedPerson $persons,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function name(): string
    {
        return 'jwt';
    }

    public function address(Client $client): AddressedAccessToken
    {
        return new AddressedAccessToken($this->signingKeyOf($client), subjectIdentifier: $this->subjects->open($client));
    }

    /**
     * Everything the KMS opens or seals is done here, so that striking the token asks nothing of the KMS.
     */
    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
    {
        $person = self::personOf($authorization);

        return new AddressedAccessToken(
            $this->signingKeyOf($authorization->client),
            $person === null ? null : $this->persons->claim($authorization->tenant, $person),
            $authorization instanceof UserAuthorizationInterface ? $this->subjects->open($authorization->client) : null,
        );
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $signIn = self::signInOf($authorization);
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'exp' => $expiresAt->getTimestamp(),
            'aud' => $authorization->audience()->claim(),
            'sub' => self::subjectOf($authorization, $addressed)->value,
            'client_id' => $authorization->client->registration->clientId,
            'iat' => $now->getTimestamp(),
            'jti' => $this->uuids->opaque()->toRfc4122(),
            ...($signIn?->authentication->toClaims() ?? []),
        ];
        $claims['scope'] = (string) $authorization->scopes;
        $requested =
            $authorization instanceof UserAuthorizationInterface && $authorization->claimsRequest !== null
                ? $authorization->claimsRequest->userinfo
                : [];
        if ($requested !== []) {
            $claims[self::USERINFO_CLAIMS] = array_keys($requested);
        }
        if ($signIn !== null) {
            $claims['sid'] = $signIn->sessionId->toRfc4122();
        }
        $details = CarriedAuthorizationDetails::of($authorization);
        if ($details !== null) {
            $claims[self::AUTHORIZATION_DETAILS] = $details->toClaim();
        }
        $claims[self::GRANT_ID] = $authorization->grantId->toRfc4122();
        $actor = $authorization instanceof NamesItsSubjectInterface ? $authorization->actor : null;
        if ($actor !== null) {
            $claims[self::ACTOR] = $actor->toClaim();
        }
        if (self::personOf($authorization) !== null) {
            $claims[self::PERSON] = $addressed->person();
        }
        $mayAct = $authorization->client->registration->mayAct;
        if ($mayAct !== null) {
            $claims[self::MAY_ACT] = $mayAct->toClaim();
        }
        $claims = [...$claims, ...($authorization->confirmation?->toClaims() ?? [])];

        $jws = $addressed->signingKey()->sign(JwtPayload::encode($claims), [
            'typ' => self::TYPE,
        ]);

        return new AccessToken($jws, $now, $expiresAt);
    }

    /**
     * @throws KeyNotFoundException when the tenant has no active key for that algorithm
     * @throws KmsUnavailableException
     */
    private function signingKeyOf(Client $client): OpenedSigningKeyInterface
    {
        return $this->signer->open($client->tenant, $this->algorithms->defaultAlgorithm());
    }

    private static function personOf(AuthorizationInterface $authorization): ?Subject
    {
        return $authorization instanceof NamesItsSubjectInterface ? $authorization->person() : null;
    }

    /**
     * RFC 9068 §2.2
     *
     * @throws LogicException when somebody signed in and the token was addressed with no kind of "sub" opened
     */
    private static function subjectOf(AuthorizationInterface $authorization, AddressedAccessToken $addressed): Subject
    {
        if ($authorization instanceof NamesItsSubjectInterface) {
            return $authorization->subject;
        }

        return $authorization instanceof UserAuthorizationInterface
            ? $addressed->subjectIdentifier()->subjectOf($authorization->user)
            : ClientSubject::of($authorization->client);
    }

    /**
     * RFC 9068 §2.2.1
     *
     * A subject named elsewhere keeps the sign-in it descends from, so the new token is asked what the old one was.
     */
    private static function signInOf(AuthorizationInterface $authorization): ?TokenSignIn
    {
        if ($authorization instanceof NamesItsSubjectInterface) {
            return $authorization->signIn;
        }

        return $authorization instanceof UserAuthorizationInterface
            ? new TokenSignIn($authorization->session->id, $authorization->authentication)
            : null;
    }
}
