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
 * says none, and names that client in its "sub" (RFC 6749 §4.4, RFC 9068 §2.2). What the provider asks of
 * a session and of a user it asks of the first and never of the second.
 *
 * A token somebody else holds for the subject says who (RFC 8693 §4.1): the chain of actors is what makes a
 * delegation visible where an impersonation shows nothing, and it is read back as it was written, the actor
 * about to use the token outermost.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param TokenAudience $audience who the token is addressed to (RFC 8707 §2), the client itself when the request that got it named no resource
     * @param Subject $subject the "sub" of the token: the pairwise subject of the user who signed in (OIDC Core §8), or the client itself when nobody did (RFC 9068 §2.2)
     * @param TokenSignIn|null $signIn the sign-in the token descends from, null for a token a client holds for itself
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5, empty when the client asked for none
     * @param ConfirmationInterface|null $confirmation what the token is bound to (RFC 8705 §3, RFC 9449 §6.1), null for a bearer token
     * @param Actor|null $actor who holds the token on behalf of its subject (RFC 8693 §4.1), null when nobody does and the holder is the subject
     * @param AuthorizationDetails|null $authorizationDetails what the token carries beyond its scopes (RFC 9396 §7), null when it carries none
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
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }
}
