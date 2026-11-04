<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ClaimsProviderInterface;

/**
 * OIDC Core §5.5
 */
final readonly class ClaimsAskedByName
{
    public function __construct(
        private ClaimsProviderInterface $claims,
    ) {
    }

    public function grantable(Client $client, ?ClaimsRequest $request): ?ClaimsRequest
    {
        return $request?->narrowedTo(new ClaimNames($this->claims->claimsOf($client->registration->allowedScopes)));
    }

    public function toAgreeTo(AuthorizationRequest $request): ClaimNames
    {
        $asked = $this->grantable($request->client, $request->claims)?->claimNames() ?? new ClaimNames();

        return $asked->without(new ClaimNames($this->claims->claimsOf($request->scopes)));
    }

    public function agreedIn(Consent $consent, AuthorizationRequest $request): bool
    {
        return $consent->coversClaims($this->toAgreeTo($request)->without(new ClaimNames($this->claims->claimsOf($consent->scopes))));
    }
}
