<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;

/**
 * The claims about a user (OIDC Core §5.1): those the scopes stand for (§5.4) and those asked for by name
 * (§5.5). Not "sub", not the protocol claims. A claim without a value is left out, an unknown one is no
 * error; every value is what the JSON will carry. The provider also says what it serves (OIDC Discovery §3),
 * and which of its claims each scope stands for, which is what a claim asked for by name is held to.
 */
interface ClaimsProviderInterface
{
    /**
     * @param Scopes|null $scopes null when no claim is due to a scope: an ID token carries what was
     *                            asked for by name and nothing the scopes would add (OIDC Core §5.4)
     * @param array<string, ClaimRequest> $requested by name, for the place answered, every one of them
     *                                               a claim the caller may be told
     *
     * @return array<string, mixed> by claim name
     */
    public function claims(User $user, ?Scopes $scopes, array $requested): array;

    /**
     * The claims of this provider these scopes stand for (OIDC Core §5.4), none for a scope it does not
     * serve. It is what a claim a client asks for by name is held to, a client registering scopes and never
     * claims (RFC 7591 §2): a claim no scope stands for is told to no client by name.
     *
     * @return list<string>
     */
    public function claimsOf(Scopes $scopes): array;

    /**
     * @return list<Scope>
     */
    public function supportedScopes(): array;

    /**
     * @return list<string>
     */
    public function supportedClaims(): array;
}
