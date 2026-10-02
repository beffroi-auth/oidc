<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * What reads an "authorization_details" back (RFC 9396 §2): the parameter of a request, as text, and the
 * claim of an access token this provider wrote, already decoded. Both go through the types the provider
 * is wired with, which are the only things that know what any of it means.
 *
 * The two readings are one reading: a token carries what a request asked for, so what is refused of a
 * request is refused of a token, and a token carrying a type the provider no longer serves is a token it
 * no longer describes.
 */
interface AuthorizationDetailsReaderInterface
{
    /**
     * The "authorization_details" parameter, as the request carried it (RFC 9396 §2).
     *
     * @throws InvalidArgumentException when it is not a JSON array of objects each naming a type the
     *                                 provider serves, or when a detail is not one of its type
     */
    public function fromJson(string $json): AuthorizationDetails;

    /**
     * The "authorization_details" claim of an access token (RFC 9396 §7), or the member of an
     * introspection response (§9), as it was decoded.
     *
     * @throws InvalidArgumentException when it is not what this provider writes there
     */
    public function fromClaim(mixed $claim): AuthorizationDetails;
}
