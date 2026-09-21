<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * A method whose client is recognised by what its certificate says about it (RFC 8705 §2.1): the
 * registration carries exactly one of the five values of §2.1.2, and a registration that carries none is
 * a registration that cannot work, refused when it is read. It carries nothing else: what the client has
 * to register is the whole of the rule, as it is for a secret and for a key.
 */
interface CertificateIdentityBearingMethodInterface extends ClientAuthenticationMethodInterface
{
}
