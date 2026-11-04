<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified grant entitles the client to, read by the token issuers.
 */
interface AuthorizationInterface
{
    public GrantTypeName $grantType { get; }

    public Uuid $grantId { get; }

    public Client $client { get; }

    public Tenant $tenant { get; }

    public Scopes $scopes { get; }

    public Scopes $grantedScopes { get; }

    public ?ResourceIndicators $resources { get; }

    public ?ResourceIndicators $grantedResources { get; }

    public ?ConfirmationInterface $confirmation { get; }

    public function audience(): TokenAudience;

    /**
     * The subject of the person's account, never the "sub" the client sees (OIDC Core §8.1); null for nobody.
     */
    public function person(): ?Subject;

    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredAccessToken;
}
