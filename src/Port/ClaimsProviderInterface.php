<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * The claims about a user (OIDC Core §5.1): those the scopes stand for (§5.4) and those asked for by name
 * (§5.5). Not "sub", not the protocol claims. A claim without a value is left out, an unknown one is no
 * error; every value is what the JSON will carry. The provider also says what it serves (OIDC Discovery §3).
 */
interface ClaimsProviderInterface
{
    /**
     * @param list<Scope> $scopes
     * @param array<string, ClaimRequest> $requested by name, for the place answered
     *
     * @return array<string, mixed> by claim name
     */
    public function claims(User $user, array $scopes, array $requested): array;

    /**
     * @return list<Scope>
     */
    public function supportedScopes(): array;

    /**
     * @return list<string>
     */
    public function supportedClaims(): array;
}
