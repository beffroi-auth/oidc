<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTargetException;

/**
 * RFC 8707 §2.2
 */
final readonly class RequestedResources
{
    /**
     * @throws InvalidTargetException when it names a resource the authorization does not carry
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
