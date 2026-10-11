<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token whose subject was named by what the client presented (architecture §4.6): the
 * record of a token exchange (RFC 8693 §2.1) or of an assertion of an issuer the tenant trusts
 * (RFC 7523 §2.1).
 *
 * It keeps the "sub" as it was named, because nothing here could resolve it again: the party that named it
 * is a token this provider issued or an issuer somebody else runs. It keeps what that token said of a
 * sign-in, the identifier of the session and what it had proven, so that its introspection renders the same
 * "sid", "auth_time", "acr" and "amr" as the token it came from, and so that a resource of this provider
 * keeps asking of it whether that session has ended. It keeps the chain of actors, which is what makes a
 * delegation visible where an impersonation shows nothing (§4.1).
 *
 * **It keeps the person beside the subject it was named by** (issue #593), when whoever read the presented
 * token resolved one: the "sub" above means something for the client that token was written for and for no
 * other, where this row names the client that asked, so a lookup under that client would find nobody under
 * a pairwise kind (OIDC Core §8.1) and the wrong certainty under a public one. The exchange had the person
 * at hand when it read what was presented (AccessTokenInspector); keeping it is what lets the acts of this
 * token be written in the journal of that person, the revocation as much as the issuance. It is null when
 * nothing read the subject back as somebody this provider serves, which is what a token a client holds for
 * itself is (RFC 6749 §4.4) and what an assertion about nobody known here would be.
 *
 * The session is kept as its identifier and not as the row of one: what named it is a token, which carries
 * a "sid" and not a session. Ending that session does not remove this row, as it does for a token granted
 * under it; every resource of this provider refuses the token all the same (AccessTokenInspector), and the
 * row goes when it expires, which is the same guarantee the self-contained shape gives.
 */
final readonly class StoredSubjectAccessToken extends StoredAccessToken
{
    /**
     * @param Subject|null $person the person this token is in the name of, by the subject their account carries, null when nothing read the named subject back as one (issue #593)
     * @param ResourceIndicators $resources the resources this token is addressed to, at least one
     * @param Uuid|null $sessionId the session the presented token named (OIDC Front-Channel Logout §3), null when it named none
     * @param AuthenticationSnapshot|null $authentication what that session had proven, null when there was none
     * @param Actor|null $actor who acts for the subject (RFC 8693 §4.1), null for an impersonation
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $tokenHash,
        Uuid $grantId,
        Client $client,
        public Subject $subject,
        public ?Subject $person,
        Scopes $scopes,
        ResourceIndicators $resources,
        public ?Uuid $sessionId,
        public ?AuthenticationSnapshot $authentication,
        public ?Actor $actor,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        ?ConfirmationInterface $confirmation = null,
    ) {
        if (($sessionId === null) !== ($authentication === null)) {
            throw new InvalidArgumentException('A token that names the session it descends from keeps what that session had proven, and one that names none keeps neither (RFC 9068 section 2.2.1).');
        }
        parent::__construct($tokenHash, $grantId, $client, $scopes, $resources, $issuedAt, $expiresAt, $confirmation);
    }

    /**
     * The person this token is in the name of, read off the row and asked of nobody: it was resolved once,
     * where the presented token was read, by the client that token had been written for.
     */
    public function person(): ?Subject
    {
        return $this->person;
    }

    /**
     * The sign-in the token descends from, null when it descends from none: the pair the issuers write and
     * the introspection renders, read back from the two columns that keep it.
     */
    public function signIn(): ?TokenSignIn
    {
        return $this->sessionId === null || $this->authentication === null
            ? null
            : new TokenSignIn($this->sessionId, $this->authentication);
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromAuthorization(
        string $tokenHash,
        SubjectAuthorization $authorization,
        DateTimeImmutable $now,
        DateTimeImmutable $expiresAt,
    ): self {
        $signIn = $authorization->signIn;

        return new self(
            $tokenHash,
            $authorization->grantId,
            $authorization->client,
            $authorization->subject,
            $authorization->person,
            $authorization->scopes,
            $authorization->resources,
            $signIn?->sessionId,
            $signIn?->authentication,
            $authorization->actor,
            $now,
            $expiresAt,
            $authorization->confirmation,
        );
    }
}
