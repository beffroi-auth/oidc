<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * The shared secret of a client, kept in the shape the method it registered can verify against: a hash
 * for the methods the secret is presented to (RFC 6749 §2.3.1), the secret itself for the one that has
 * to compute a MAC with it (OIDC Core §9). A method says which shapes it accepts
 * (SecretBearingMethodInterface); nothing else in the provider reads a secret.
 */
interface ClientSecretInterface
{
}
