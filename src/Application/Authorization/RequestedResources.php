<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTargetException;

/**
 * RFC 8707 §2.1
 */
final readonly class RequestedResources
{
    /**
     * @param list<string> $values
     *
     * @throws InvalidTargetException
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
