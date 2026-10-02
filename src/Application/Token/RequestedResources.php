<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTargetException;

/**
 * What a token request asks its access token to be addressed to (RFC 8707 §2.2). Every grant that
 * spends an authorization reads it the same way, so it is read here once: a request that names no
 * resource takes the resources of the authorization it spends, one that names a subset of them is
 * served that subset, and one that names anything else is refused with "invalid_target".
 *
 * Narrowing never widens: the resources a grant carries were named at the authorization endpoint,
 * against what the client registered, and a token request is not another chance to ask.
 */
final readonly class RequestedResources
{
    /**
     * @param ResourceIndicators|null $granted the resources of the authorization being spent, null when it carries none
     *
     * @throws InvalidTargetException when a value is not an absolute URI, or names a resource the
     *                                authorization does not carry
     *
     * @return ResourceIndicators|null null when the request narrows nothing
     */
    public static function of(RequestParameters $request, ?ResourceIndicators $granted): ?ResourceIndicators
    {
        $values = $request->repeated('resource');
        if ($values === []) {
            return null;
        }
        try {
            $requested = ResourceIndicators::of($values);
        } catch (InvalidArgumentException $exception) {
            throw InvalidTargetException::notAnAbsoluteUri(previous: $exception);
        }
        if ($granted === null || ! $granted->covers($requested)) {
            throw InvalidTargetException::notGranted();
        }

        return $requested;
    }
}
