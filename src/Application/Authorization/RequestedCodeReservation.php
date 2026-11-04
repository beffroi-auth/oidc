<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidRequestException;

/**
 * RFC 9449 §10
 */
final readonly class RequestedCodeReservation
{
    /**
     * @throws InvalidRequestException
     */
    public static function of(?string $thumbprint): ?KeyConfirmation
    {
        if ($thumbprint === null) {
            return null;
        }
        try {
            return new KeyConfirmation($thumbprint);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidRequestException(
                'The dpop_jkt parameter is the JWK thumbprint of a key, the base64url of a SHA-256 (RFC 9449 section 10).',
                true,
                $exception,
            );
        }
    }
}
