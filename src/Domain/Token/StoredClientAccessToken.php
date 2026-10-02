<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token a client holds for itself (RFC 6749 §4.4, architecture §4.6): the record of what
 * it is good for and of nothing else. There is no session behind it, so the row has no session to point
 * at, nothing of an "auth_time", an "acr" or an "amr" to keep, and no claims about a user to have been
 * asked for; what its introspection names in "sub" is the client itself (RFC 9068 §2.2).
 *
 * It is addressed to the resources the request named, which this grant requires (RFC 8707 §2), so its
 * "aud" never falls back to the client that asked for it.
 */
final readonly class StoredClientAccessToken extends StoredAccessToken
{
    /**
     * @param ResourceIndicators $resources the resources this token is addressed to, at least one
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $tokenHash,
        Uuid $grantId,
        Client $client,
        Scopes $scopes,
        ResourceIndicators $resources,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        ?ConfirmationInterface $confirmation = null,
    ) {
        parent::__construct($tokenHash, $grantId, $client, $scopes, $resources, $issuedAt, $expiresAt, $confirmation);
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromAuthorization(string $tokenHash, ClientAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): self
    {
        return new self(
            $tokenHash,
            $authorization->grantId,
            $authorization->client,
            $authorization->scopes,
            $authorization->resources,
            $now,
            $expiresAt,
            $authorization->confirmation,
        );
    }
}
