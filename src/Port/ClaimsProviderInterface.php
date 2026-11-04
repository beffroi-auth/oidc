<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;

/**
 * OIDC Core §5.1, §5.4, §5.5
 *
 * Never "sub" nor a protocol claim; a claim without a value is left out, and an unknown one is no error.
 */
interface ClaimsProviderInterface
{
    /**
     * @param Scopes|null $scopes null when no claim is due to a scope
     * @param array<string, ClaimRequest> $requested by claim name, each one the caller may be told
     *
     * @return array<string, mixed> by claim name
     */
    public function claims(User $user, ?Scopes $scopes, array $requested): array;

    /**
     * OIDC Core §5.4
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
