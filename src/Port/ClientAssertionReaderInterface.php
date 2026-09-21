<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ClientAssertion;
use Heidi\Oidc\Exception\InvalidClientAssertionException;

/**
 * Reads a client assertion without verifying anything (RFC 7523 §2.2): the header names the algorithm
 * and the key, the claims name the client. A provider has to read that much before it can know which
 * client and which key would verify it; nothing read here is trusted until a verifier has spoken.
 */
interface ClientAssertionReaderInterface
{
    /**
     * @throws InvalidClientAssertionException when the string is not a compact JWS carrying a JSON object
     */
    public function read(string $assertion): ClientAssertion;
}
