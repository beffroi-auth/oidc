<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\JwtLibrary;

use Heidi\Oidc\Domain\Client\ClientAssertion;
use Heidi\Oidc\Exception\InvalidClientAssertionException;
use Heidi\Oidc\Port\ClientAssertionReaderInterface;
use function is_array;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use Throwable;

/**
 * Reads a client assertion with web-token/jwt-library, and verifies nothing (RFC 7523 §2.2): the
 * serialization is undone, the protected header and the claims are read as they are, and what they say
 * is only what the sender claims until a verifier has spoken.
 */
final readonly class JwtLibraryClientAssertionReader implements ClientAssertionReaderInterface
{
    private CompactSerializer $serializer;

    public function __construct()
    {
        $this->serializer = new CompactSerializer();
    }

    public function read(string $assertion): ClientAssertion
    {
        try {
            $jws = $this->serializer->unserialize($assertion);
        } catch (Throwable $exception) {
            throw new InvalidClientAssertionException('The client assertion is not a compact JWS.', 0, $exception);
        }
        if ($jws->countSignatures() !== 1) {
            throw new InvalidClientAssertionException('A client assertion carries exactly one signature.');
        }
        $payload = $jws->getPayload();
        if ($payload === null) {
            throw new InvalidClientAssertionException('A client assertion carries its claims; a detached payload is refused.');
        }
        try {
            $claims = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new InvalidClientAssertionException('The claims of a client assertion are a JSON object (RFC 7519 section 7.2).', 0, $exception);
        }
        if (! is_array($claims)) {
            throw new InvalidClientAssertionException('The claims of a client assertion are a JSON object (RFC 7519 section 7.2).');
        }

        /** @var array<string, mixed> $claims */
        return new ClientAssertion($assertion, $jws->getSignature(0)->getProtectedHeader(), $claims);
    }
}
