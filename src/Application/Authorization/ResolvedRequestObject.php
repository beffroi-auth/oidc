<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Domain\Authorization\RequestObject;

/**
 * What an endpoint has in hand once a request arrived in a JWT (RFC 9101 §6.1): the parameters it reads
 * in place of the ones it received, and the object they came out of.
 *
 * The parameters are the request, and every endpoint that reads one reads them the same way. The object
 * is what carried it, and an endpoint whose rule is about the carrier rather than about the request
 * reads it here: CIBA Core §7.1.1 asks a backchannel authentication request for claims the parameters of
 * an authorization request never carry, "iat" and "jti" being what a JWT says about itself and not what
 * a client asks for.
 */
final readonly class ResolvedRequestObject
{
    /**
     * @param RequestObject $object the object the request arrived in, its signature verified and its
     *                              claims validated
     * @param array<string, string|list<string>> $parameters the parameters the endpoint reads
     */
    public function __construct(
        public RequestObject $object,
        public array $parameters,
    ) {
    }
}
