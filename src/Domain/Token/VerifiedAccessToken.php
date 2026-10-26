<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified access token says, whatever its shape (RFC 9068 §4, architecture §4.6). Neither the
 * user nor the grant is looked up here.
 *
 * A token somebody signed in for says which sign-in it descends from; a token a client holds for itself
 * says none, and names that client in its "sub" (RFC 6749 §4.4, RFC 9068 §2.2); a token issued for a person
 * nobody signed in for here, on the assertion of an issuer the tenant trusts (RFC 7523 §2.1) or by the
 * exchange of such a token (RFC 8693 §2.1), says none either and says who it is about. What the provider
 * asks of a session it asks of the first alone, and what it asks of a person it asks of every token that
 * names one (namesAPerson()), never of the second.
 *
 * A token somebody else holds for the subject says who (RFC 8693 §4.1): the chain of actors is what makes a
 * delegation visible where an impersonation shows nothing, and it is read back as it was written, the actor
 * about to use the token outermost.
 *
 * **It says who it is about where whoever read it back knew** (issue #601): the "sub" above means something
 * for the client the token was written for and for no other (OIDC Core §8.1), so a token whose subject
 * another client named keeps a name the client holding it never sees (RFC 8693 §2.2.1). Each shape answers
 * for the person out of what it has: the one the provider keeps a record of off that record, where it was
 * resolved once, and the one that carries its own claims off a claim it carries sealed (issue #641). A token
 * nothing resolved a person for says nobody, and the "sub" is then all there is to read.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param TokenAudience $audience who the token is addressed to (RFC 8707 §2), the client itself when the request that got it named no resource
     * @param Subject $subject the "sub" of the token: the name a client knows its person by (OIDC Core §8), or the client itself when the token is nobody's (RFC 9068 §2.2)
     * @param TokenSignIn|null $signIn the sign-in the token descends from, null when nobody signed in for it here
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5, empty when the client asked for none
     * @param ConfirmationInterface|null $confirmation what the token is bound to (RFC 8705 §3, RFC 9449 §6.1), null for a bearer token
     * @param Actor|null $actor who holds the token on behalf of its subject (RFC 8693 §4.1), null when nobody does and the holder is the subject
     * @param AuthorizationDetails|null $authorizationDetails what the token carries beyond its scopes (RFC 9396 §7), null when it carries none
     * @param Subject|null $person the person the token is about, by the subject their account carries (issue #588), null when whatever read the token resolved nobody
     */
    public function __construct(
        public Client $client,
        public TokenAudience $audience,
        public Subject $subject,
        public Uuid $grantId,
        public ?Scopes $scopes,
        public ?TokenSignIn $signIn,
        public array $userinfoClaims,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
        public ?Actor $actor = null,
        public ?AuthorizationDetails $authorizationDetails = null,
        public ?Subject $person = null,
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }

    /**
     * Whether the token is somebody's (issue #831): it descends from a sign-in, or it says who it is about
     * where nobody signed in for it here (RFC 7523 §2.1, RFC 8693 §2.1). A token a client holds for itself
     * is nobody's (RFC 6749 §4.4).
     */
    public function namesAPerson(): bool
    {
        return $this->signIn !== null || $this->person !== null;
    }
}
