<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTargetException;

/**
 * What the "resource" parameter of an authorization request must be (RFC 8707 §2.1), judged against the
 * client that sends it, the counterpart of the class of the same name that judges it at the token
 * endpoint against the grant being spent (Application\Token\RequestedResources).
 */
final readonly class RequestedResources
{
    /**
     * The resources the tokens of this request will be addressed to, named once each or several times
     * over. What a client may ask for is what it registered, as every other list of a client is: a
     * resource outside it is "invalid_target", and so is a value that is not an absolute URI. A request
     * that names none asks for none, and its tokens are addressed to the client itself.
     *
     * @param list<string> $values
     *
     * @throws InvalidTargetException when a value is not an absolute URI, or names a resource the
     *                                client is not registered for
     */
    public static function of(Client $client, array $values): ?ResourceIndicators
    {
        if ($values === []) {
            return null;
        }
        try {
            $resources = ResourceIndicators::of($values);
        } catch (InvalidArgumentException $exception) {
            throw InvalidTargetException::notAnAbsoluteUri(true, $exception);
        }
        if (! $client->registration->allowsResources($resources)) {
            throw InvalidTargetException::notRegistered(true);
        }

        return $resources;
    }
}
