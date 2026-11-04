<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidScopeException;

/**
 * RFC 6749 §3.3, OIDC Core §3.1.2.2
 */
final readonly class RequestedScopes
{
    /**
     * @throws InvalidScopeException
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
                throw InvalidScopeException::notRegistered(true);
            }
        }
        if (! $scopes->has(Scope::openid())) {
            throw new InvalidScopeException('The scope parameter must contain openid (OIDC Core section 3.1.2.1).', true);
        }

        return $scopes;
    }
}
