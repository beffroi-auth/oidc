<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use function is_array;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use Throwable;

/**
 * Verifies nothing: the header and the claims it reads are only what the sender claims.
 */
final readonly class JwtLibraryCompactJwtReader implements CompactJwtReaderInterface
{
    private CompactSerializer $serializer;

    public function __construct()
    {
        $this->serializer = new CompactSerializer();
    }

    public function read(string $jwt): UnverifiedJwt
    {
        try {
            $jws = $this->serializer->unserialize($jwt);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The token is not a compact JWS.', 0, $exception);
        }
        if ($jws->countSignatures() !== 1) {
            throw new InvalidJwtException('A token a client signs carries exactly one signature.');
        }
        $payload = $jws->getPayload();
        if ($payload === null) {
            throw new InvalidJwtException('A token a client signs carries its claims; a detached payload is refused.');
        }
        try {
            $claims = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The claims of a token are a JSON object (RFC 7519 section 7.2).', 0, $exception);
        }
        if (! is_array($claims)) {
            throw new InvalidJwtException('The claims of a token are a JSON object (RFC 7519 section 7.2).');
        }

        /** @var array<string, mixed> $claims */
        return new UnverifiedJwt($jwt, $jws->getSignature(0)->getProtectedHeader(), $claims);
    }
}
