<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Token\InspectedAccessToken;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use SensitiveParameter;

/**
 * What the provider's own resources ask of an access token (architecture §4.6, §4.7, §4.12): verified,
 * descending from a session that has not ended and from a grant still alive, naming a user still served.
 *
 * The questions are asked here, in one way for both shapes of token: what an "at+jwt" carries as "sid" and
 * "grant_id" is what the record of an opaque token carries as a row, and a resource of the provider is the
 * one reader able to resolve either. A resource server that holds the token and the published keys and
 * nothing else cannot ask them, which is what verifying offline means (RFC 9068 §4); the provider never
 * has that excuse.
 *
 * Each question is asked of the tokens that can answer it. A token somebody signed in for answers for its
 * session, its grant and its person. A token issued for a person nobody signed in for here, on the
 * assertion of an issuer the tenant trusts (RFC 7523 §2.1) or by the exchange of such a token
 * (RFC 8693 §2.1), descends from no sign-in and answers for its person all the same (issue #831): a person
 * this provider no longer serves is refused wherever a token names them. A token a client holds for itself
 * descends from no sign-in and names nobody (RFC 6749 §4.4), so none of the three is asked of it and none
 * is answered in its favour by default. What the token says, the sign-in it descends from and the person it
 * is about, is what decides, never the name of the grant that issued it: the grant is looked for among the
 * records every flow of this provider writes (RecordedGrantsInterface), so a token of a flow that draws no
 * authorization code answers for its grant as an ordinary one does.
 *
 * The person is asked of the token and never read off its "sub" here (PersonOfAnAccessToken): a token says
 * who it is about where that was resolved once, off the record the provider keeps of it or off a claim it
 * carries sealed, and a token that says nobody is the one whose "sub" is read, for the client it was written
 * for. Which it is is the token's business and not this one's, so a token whose subject another client named
 * is answered for by the person the exchange that issued it had at hand, in either shape
 * (RFC 8693 §2.2.1, issues #601 and #641).
 */
final readonly class AccessTokenInspector
{
    public function __construct(
        private AccessTokenVerifier $tokens,
        private AuthenticationSessionRepositoryInterface $sessions,
        private RecordedGrantsInterface $grants,
        private PersonOfAnAccessToken $persons,
    ) {
    }

    /**
     * @throws InvalidTokenException
     */
    public function inspect(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): InspectedAccessToken
    {
        $token = $this->tokens->verify($tenant, $accessToken, $now);
        $signIn = $token->signIn;
        if ($signIn !== null) {
            $session = $this->sessions->find($signIn->sessionId);
            if ($session === null || $session->hasEnded()) {
                throw new InvalidTokenException('The access token descends from a session this provider ended.');
            }
            $grant = $this->grants->findByGrantId($token->grantId);
            if ($grant === null || $grant->isRevoked()) {
                throw new InvalidTokenException('The access token descends from a grant this provider revoked.');
            }
        }
        if (! $token->namesAPerson()) {
            return new InspectedAccessToken($token, null);
        }
        $user = $this->persons->of($token);
        if ($user === null || ! $user->isEnabled()) {
            throw new InvalidTokenException('The access token names a user this provider no longer serves.');
        }

        return new InspectedAccessToken($token, $user);
    }
}
