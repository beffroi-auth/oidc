<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * The claims about a user that a response may carry (OIDC Core §5.1): those the scopes stand for (§5.4)
 * and those a client asked for by name (§5.5). "sub" is not among them: it comes from the subject
 * identifier resolver, and the protocol claims of a token ("iss", "aud", "exp" and the like) are the
 * issuer's. A claim the user has no value for is left out (§5.3.2: "not all Claims will be available");
 * a request for a claim the provider does not know is not an error either.
 *
 * Every value is what the JSON will carry: a boolean is a PHP bool, a date is an integer, an address is
 * a map. Nothing of it is stringified.
 *
 * A provider also says what it serves, for the discovery document (OIDC Discovery §3 "scopes_supported"
 * and "claims_supported"): the scopes it gives a meaning to and the claim names it may supply values for.
 * "openid", "offline_access" and "sub" are not a provider's to announce.
 */
interface ClaimsProviderInterface
{
    /**
     * @param list<Scope> $scopes the scopes whose claims are due (§5.4)
     * @param array<string, ClaimRequest> $requested the claims asked for by name (§5.5), as the claims request lists them for the place answered
     *
     * @return array<string, mixed> claim name to JSON value
     */
    public function claims(User $user, array $scopes, array $requested): array;

    /**
     * @return list<Scope> the scopes this provider serves claims for (§5.4)
     */
    public function supportedScopes(): array;

    /**
     * @return list<string> the claim names this provider may supply a value for (§5.1)
     */
    public function supportedClaims(): array;
}
