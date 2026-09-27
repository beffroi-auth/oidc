<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidScopeException;

/**
 * What the "scope" parameter of an authorization request must be (RFC 6749 §3.3, OIDC Core §3.1.2.2
 * step 3), judged against the client that sends it: a list of scope tokens, every one of them allowed to
 * that client, "openid" among them.
 *
 * The counterpart of what the token endpoint does with the same parameter (Application\Token): there a
 * scope is narrowed against the grant being spent, here it is checked against the registration, and the
 * two rules are two classes because they are two rules.
 */
final readonly class RequestedScopes
{
    /**
     * @throws InvalidScopeException when it is not a list of scope tokens, when it names a scope the
     *                               client is not allowed, or when it does not name "openid"
     */
    public static function of(Client $client, string $scope): Scopes
    {
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(true, $exception);
        }
        foreach ($scopes->all as $candidate) {
            if (! $client->registration->allowedScopes->has($candidate)) {
                throw new InvalidScopeException('The requested scope is not allowed for this client.', true);
            }
        }
        if (! $scopes->has(Scope::openid())) {
            throw new InvalidScopeException('The scope parameter must contain openid (OIDC Core section 3.1.2.1).', true);
        }

        return $scopes;
    }
}
