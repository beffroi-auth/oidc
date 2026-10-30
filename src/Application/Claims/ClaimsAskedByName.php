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
 * The claims a request asks for one by one (OIDC Core §5.5), held to what its client registered and to what
 * the person agreed to (architecture §4.3). A scope asks for a set of claims, and asking for some of them
 * one by one is how a client asks the person to disclose less (§5.4); a client registers scopes and never
 * claims (RFC 7591 §2), so a claim it asks for by name is held where the scope that stands for it is held,
 * and never further.
 *
 * - **To the registration.** What a client may be told by name is what a scope it registered stands for.
 *   Another claim is not served, and asking for it is no error, a provider being free to leave a requested
 *   claim out (§5.3.2, §5.5.1).
 * - **To the consent.** The person agrees to what is released before it is (§3.1.2.4): the page lists the
 *   claims asked for by name that no scope of the request stands for, a claim one of them stands for being
 *   agreed to with it, and a consent answers for them when it holds each one by name or holds a scope that
 *   stands for it.
 *
 * What a scope stands for is what the wired claims providers say (`ClaimsProviderInterface::claimsOf()`), so a
 * claim a deployment serves is held to the scope its class names exactly as a claim of §5.1 is held to its
 * scope of §5.4.
 */
final readonly class ClaimsAskedByName
{
    public function __construct(
        private ClaimsProviderInterface $claims,
    ) {
    }

    /**
     * What a client may be told of what it asked for by name: the claims a scope it registered stands for,
     * what is asked of each kept as it was asked. It is what a code carries (architecture §4.4), and so what
     * the tokens that descend from it answer with.
     */
    public function grantable(Client $client, ?ClaimsRequest $request): ?ClaimsRequest
    {
        return $request?->narrowedTo(new ClaimNames($this->claims->claimsOf($client->registration->allowedScopes)));
    }

    /**
     * What the person is asked to agree to by name: the claims of the request the client may be told and no
     * scope of the request stands for, whichever member asks for them, each once.
     */
    public function toAgreeTo(AuthorizationRequest $request): ClaimNames
    {
        $asked = $this->grantable($request->client, $request->claims)?->claimNames() ?? new ClaimNames();

        return $asked->without(new ClaimNames($this->claims->claimsOf($request->scopes)));
    }

    /**
     * Whether a consent answers for what the request asks for by name: each claim is one it holds by name,
     * or one a scope it holds stands for.
     */
    public function agreedIn(Consent $consent, AuthorizationRequest $request): bool
    {
        return $consent->coversClaims($this->toAgreeTo($request)->without(new ClaimNames($this->claims->claimsOf($consent->scopes))));
    }
}
