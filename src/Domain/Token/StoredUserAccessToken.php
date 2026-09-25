<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token somebody signed in for (architecture §4.6): the record of the session it
 * descends from, of what that session had proven at the grant, and of the claims the client asked for by
 * name, which is what its introspection renders and what the verifier reads back as "sid", "auth_time",
 * "acr" and "amr".
 *
 * The session is kept and not only its identifier, because the "sub" a client sees is resolved for the
 * user of that session (OIDC Core §8) and the logout of the session takes the token with it.
 */
final readonly class StoredUserAccessToken extends StoredAccessToken
{
    /**
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant
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
            $authorization->claimsRequest,
            $authorization->authentication,
            $now,
            $expiresAt,
            $authorization->confirmation,
        );
    }
}
