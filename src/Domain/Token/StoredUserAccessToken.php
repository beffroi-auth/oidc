<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token somebody signed in for (architecture §4.6): the record of the session it
 * descends from, of what that session had proven at the grant, of the claims the client asked for by
 * name, and of what the user agreed to beyond the scopes (RFC 9396 §9), which is what its introspection
 * renders and what the verifier reads back as "sid", "auth_time", "acr", "amr" and "authorization_details".
 *
 * The session is kept and not only its identifier, because the "sub" a client sees is resolved for the
 * user of that session (OIDC Core §8) and the logout of the session takes the token with it.
 */
final readonly class StoredUserAccessToken extends StoredAccessToken
{
    /**
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant
     * @param AuthorizationDetails|null $authorizationDetails what this token carries beyond its scopes (RFC 9396 §7), null when the request asked for none
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $tokenHash,
        Uuid $grantId,
        Client $client,
        public AuthenticationSession $session,
        Scopes $scopes,
        ?ResourceIndicators $resources,
        public ?AuthorizationDetails $authorizationDetails,
        public ?ClaimsRequest $claimsRequest,
        public AuthenticationSnapshot $authentication,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        ?ConfirmationInterface $confirmation = null,
    ) {
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An access token binds a session and a client of the same tenant.');
        }
        parent::__construct($tokenHash, $grantId, $client, $scopes, $resources, $issuedAt, $expiresAt, $confirmation);
    }

    /**
     * The user of the session it descends from (issue #588).
     */
    public function person(): Subject
    {
        return $this->session->user->subject;
    }

    /**
     * The session it descends from, whose user is its person (issue #888), by an identifier a store hands over
     * without opening that session.
     */
    public function sessionNamingItsPerson(): Uuid
    {
        return $this->session->id;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromAuthorization(
        string $tokenHash,
        UserAuthorizationInterface $authorization,
        DateTimeImmutable $now,
        DateTimeImmutable $expiresAt,
    ): self {
        return new self(
            $tokenHash,
            $authorization->grantId,
            $authorization->client,
            $authorization->session,
            $authorization->scopes,
            $authorization->resources,
            $authorization->authorizationDetails,
            $authorization->claimsRequest,
            $authorization->authentication,
            $now,
            $expiresAt,
            $authorization->confirmation,
        );
    }

    /**
     * What a token issued on a login adds: what the request asked, and what the session proved, which the token
     * itself carries in the clear.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'claimsRequest' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
