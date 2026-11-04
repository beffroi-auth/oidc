<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.4
 */
final readonly class StoredClientAccessToken extends StoredAccessToken
{
    /**
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

    public function person(): ?Subject
    {
        return null;
    }

    public function sessionNamingItsPerson(): ?Uuid
    {
        return null;
    }

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
