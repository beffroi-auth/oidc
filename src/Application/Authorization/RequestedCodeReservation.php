<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;

/**
 * What the "dpop_jkt" parameter of an authorization request must be (RFC 9449 §10): the key the code is
 * reserved for, beside the challenge it is bound to (RequestedCodeChallenge).
 */
final readonly class RequestedCodeReservation
{
    /**
     * The key the client will exchange the code with, named by its JWK thumbprint, so that a code stolen
     * on its way back is worth nothing to whoever does not hold that key. A request that names one is a
     * request whose token exchange must prove it, whether the client pushed the request or signed it.
     *
     * @throws InvalidRequestException when the value is not the thumbprint of a key
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
