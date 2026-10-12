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
 * person was resolved once, where the subject the token carries was read by the client it had been written
 * for, and each shape keeps that answer in what it has, the opaque one a column beside the named subject
 * and the self-contained one a claim it carries sealed (issue #641). The account is then read as the
 * journal of a person reads it, by the subject it carries (issue #588).
 *
 * A token that says nobody is read by its "sub", **for the client the token was written for** and never as a
 * key of a row (OIDC Core §8): under a pairwise kind (§8.1) that string is the one that client sees, so a
 * token read as if its "sub" were the provider's own identifier would find nobody, or worse, somebody. It is
 * the reading of a token somebody signed in for, whose "sub" is the name the client holding it sees its
 * person under, and of a token a client holds for itself, which is about nobody at all (RFC 6749 §4.4) and
 * answers so.
 *
 * The two are never the same question of the same token: a token whose subject another client named
 * (RFC 8693 §2.2.1) carries a "sub" the client that holds it never sees, so asking that client would look
 * one client's name up under another, and that is the token which says who it is about rather than leave it
 * to be looked up.
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
