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

final readonly class StoredUserAccessToken extends StoredAccessToken
{
    /**
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

    public function person(): Subject
    {
        return $this->session->user->subject;
    }

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
