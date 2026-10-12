<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;

/**
 * The person a verified access token is about (architecture §4.6, §4.7), null when nothing names one: the one
 * question a resource of the provider asks of a token it holds, asked in one way for every shape.
 *
 * A token that says who it is about is read by that name and nothing is resolved again (issue #601): the
 * record the provider keeps names the person beside the subject the token was written under, resolved once
 * where it was resolvable, so the account is read as the journal of a person reads it, by the subject it
 * carries (issue #588).
 *
 * A token that says nobody is read by its "sub", **for the client the token was written for** and never as a
 * key of a row (OIDC Core §8): under a pairwise kind (§8.1) that string is the one that client sees, so a
 * token read as if its "sub" were the provider's own identifier would find nobody, or worse, somebody. A
 * "sub" is all a self-contained token says of who it is about, which is why that is the one shape this
 * still asks for.
 *
 * The two are never the same question of the same token: a token whose subject another client named
 * (RFC 8693 §2.2.1) keeps a "sub" the client that holds it never sees, so asking that client would look one
 * client's name up under another, and a token a client holds for itself is about nobody at all
 * (RFC 6749 §4.4) and answers so.
 */
final readonly class PersonOfAnAccessToken
{
    public function __construct(
        private UserRepositoryInterface $users,
        private PresentedSubjectReaderInterface $subjects,
    ) {
    }

    /**
     * Null when the token names nobody this provider serves, which a resource of the provider reads as a
     * token it has nothing to answer for.
     */
    public function of(VerifiedAccessToken $token): ?User
    {
        $person = $token->person;

        return $person === null
            ? $this->subjects->findUser($token->client, $token->subject)
            : $this->users->findBySubject($token->client->tenant, $person);
    }
}
