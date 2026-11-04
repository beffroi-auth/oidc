<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
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
 * An opaque access token whose subject was named by what the client presented (RFC 8693 §2.1, RFC 7523 §2.1).
 *
 * Ending its session does not remove the row: AccessTokenInspector refuses the token all the same, and the row
 * goes when it expires.
 */
final readonly class StoredSubjectAccessToken extends StoredAccessToken
{
    /**
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

    public function person(): ?Subject
    {
        return $this->person;
    }

    public function sessionNamingItsPerson(): ?Uuid
    {
        return null;
    }

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

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'subject' => new NoPersonalDatum(Reason::THE_SUBJECT),
            'person' => new NoPersonalDatum(Reason::THE_SUBJECT),
            'sessionId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'actor' => new NoPersonalDatum('the actor a delegated token names, which is a client and never a person (RFC 8693 §4.1)'),
        ];
    }
}
