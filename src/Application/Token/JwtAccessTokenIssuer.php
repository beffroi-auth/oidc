<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Port\UuidGeneratorInterface;
use function array_keys;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
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
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * RFC 9068 (architecture §4.6): "typ" is "at+jwt" (§2.1), the claims are those of §2.2 and §2.2.1, "scope"
 * in the syntax of RFC 8693 §4.2, "aud" the resources the request asked the token for (RFC 8707 §2) and
 * the client itself when it asked for none. A token somebody signed in for names them in "sub" and says
 * which sign-in it descends from; a token a client holds for itself names that client (§2.2) and carries
 * no "sid", no "auth_time", no "acr" and no "amr", there being nobody to describe (RFC 6749 §4.4).
 * Which of the two a token is, the authorization says by what it is, never the name of the grant. A token
 * whose subject was named by what the client presented says what was named and derives nothing
 * (NamesItsSubjectInterface): the "sub" and the sign-in of the token it descends from, as they stood, plus the
 * "act" of whoever acts for that subject (RFC 8693 §4.1). "may_act" says who may act for the subject of a
 * token of this client (§4.4), which its registration decides and which is written so that a resource server
 * verifying the token offline reads the same rule the provider applies. Three private claims (RFC 7519 §4.3): "grant_id"
 * names the code the token descends from, "userinfo_claims" what the client asked for by name (OIDC Core §5.5), and
 * "person" who the token is about when its "sub" says that to nobody but another client, sealed under the KMS of the
 * tenant (SealedPerson).
 * Nothing is stored: the token is its own record. An access token is read by resource servers, not by the
 * client, so it is signed with the algorithm the provider signs with by default, never the one the client
 * registered for its ID tokens. A token issued on a request that proved a key carries the "cnf" of
 * RFC 7800 §3.1, which is what binds it to that key (RFC 8705 §3). The key it is signed with is opened when
 * the token is addressed, which a grant somebody signed in for does before it spends what the request
 * presented, and the token is signed under the key that was opened.
 */
final readonly class JwtAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public const string TYPE = 'at+jwt';

    public const string USERINFO_CLAIMS = 'userinfo_claims';

    public const string GRANT_ID = 'grant_id';

    /**
     * Issue #641: the person the token is about, sealed, for the one shape of authorization whose "sub"
     * names nobody to the client that holds the token (RFC 8693 §2.2.1).
     */
    public const string PERSON = 'person';

    /**
     * RFC 8693 §4.1.
     */
    public const string ACTOR = 'act';

    /**
     * RFC 8693 §4.4.
     */
    public const string MAY_ACT = 'may_act';

    /**
     * RFC 9396 §7.
     */
    public const string AUTHORIZATION_DETAILS = 'authorization_details';

    public function __construct(
        private SigningKeyOpenerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        private UuidGeneratorInterface $uuids,
        private SealedPerson $persons,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    /**
     * The name a client registers to receive its access tokens in this shape, which JwtAccessTokenVerifier
     * reads them back under.
     */
    public function name(): string
    {
        return 'jwt';
    }

    public function address(Client $client): AddressedAccessToken
    {
        return new AddressedAccessToken($this->signer->open($client->tenant, $this->algorithms->defaultAlgorithm()));
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $signIn = self::signInOf($authorization);
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'exp' => $expiresAt->getTimestamp(),
            'aud' => $authorization->audience()->claim(),
            'sub' => $this->subjectOf($authorization)->value,
            'client_id' => $authorization->client->registration->clientId,
            'iat' => $now->getTimestamp(),
            'jti' => $this->uuids->opaque()->toRfc4122(),
            // RFC 9068 §2.2.1: what the session had proven, of a token there is a session behind
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
        // RFC 9396 §7: what the user agreed to beyond the scopes, as this response carries it; of an
        // authorization nobody was asked for, there is nothing to write
        $details = CarriedAuthorizationDetails::of($authorization);
        if ($details !== null) {
            $claims[self::AUTHORIZATION_DETAILS] = $details->toClaim();
        }
        $claims[self::GRANT_ID] = $authorization->grantId->toRfc4122();
        // RFC 8693 §4.1: who holds the token on behalf of its subject, the most recent actor outermost;
        // absent, nobody does and whoever holds it is the subject (§1.3)
        $actor = $authorization instanceof NamesItsSubjectInterface ? $authorization->actor : null;
        if ($actor !== null) {
            $claims[self::ACTOR] = $actor->toClaim();
        }
        // issue #641: who the token is about, where the "sub" above says it to another client and to
        // nobody else (RFC 8693 §2.2.1, OIDC Core §8.1). A token somebody signed in for carries a "sub"
        // the client it was written for reads back, so there is nothing there this would add; a token a
        // client holds for itself is about nobody (RFC 6749 §4.4) and says so by carrying none
        $person = $authorization instanceof NamesItsSubjectInterface ? $authorization->person() : null;
        if ($person !== null) {
            $claims[self::PERSON] = $this->persons->claim($authorization->tenant, $person);
        }
        // RFC 8693 §4.4: who may act for the subject of a token of this client, as its registration says it
        $mayAct = $authorization->client->registration->mayAct;
        if ($mayAct !== null) {
            $claims[self::MAY_ACT] = $mayAct->toClaim();
        }
        // RFC 8705 §3.1: what the client proved at the request this token answers, so that a resource
        // server verifying the token offline knows what to ask its caller to present again
        $claims = [...$claims, ...($authorization->confirmation?->toClaims() ?? [])];

        $jws = $addressed->signingKey()->sign(JwtPayload::encode($claims), [
            'typ' => self::TYPE,
        ]);

        return new AccessToken($jws, $now, $expiresAt);
    }

    /**
     * RFC 9068 §2.2: the pairwise subject of whoever signed in (OIDC Core §8), the client itself when nobody
     * did (RFC 6749 §4.4), and the subject named by what the client presented when somebody else named it
     * (RFC 8693 §2.2.1, RFC 7523 §2.1), which is not resolved again here because it was resolved where it was
     * named.
     */
    private function subjectOf(AuthorizationInterface $authorization): Subject
    {
        if ($authorization instanceof NamesItsSubjectInterface) {
            return $authorization->subject;
        }

        return $authorization instanceof UserAuthorizationInterface
            ? $this->subjects->resolve($authorization->user, $authorization->client)
            : ClientSubject::of($authorization->client);
    }

    /**
     * RFC 9068 §2.2.1: the sign-in the token descends from, null when it descends from none. An authorization
     * whose subject was named elsewhere carries the sign-in of the token it descends from, unchanged, so that
     * the provider keeps asking of the new token what it asked of the old one.
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
