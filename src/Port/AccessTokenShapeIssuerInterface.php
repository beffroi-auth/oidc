<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;

/**
 * Writes the access tokens of one shape (architecture §4.6), the counterpart of the verifier that reads
 * them back (AccessTokenVerifierInterface). It names the shape it writes, which is the name a client
 * registers and the name the verifier of that shape answers to.
 *
 * What picks it for a token is ServedAccessTokenShapes, and it is picked by that name alone: nothing
 * reads a class, and a shape added to a deployment is a class on each side and two lines in the wiring.
 */
interface AccessTokenShapeIssuerInterface extends AccessTokenIssuerInterface, AccessTokenShapeInterface
{
}
