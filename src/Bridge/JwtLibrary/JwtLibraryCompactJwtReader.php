<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Core\Domain\Encoding\JoseExtension;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Throwable;

/**
 * RFC 7515 §4.1.11
 *
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
        $header = $jws->getSignature(0)->getProtectedHeader();
        if (JoseExtension::isNamedIn($header)) {
            throw new InvalidJwtException('The token uses an extension of JOSE this provider does not understand (RFC 7515 section 4.1.11).');
        }
        $payload = $jws->getPayload();
        if ($payload === null) {
            throw new InvalidJwtException('A token a client signs carries its claims; a detached payload is refused.');
        }
        try {
            $claims = JwtPayload::decode($payload, 512);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The claims of a token are a JSON object (RFC 7519 section 7.2).', 0, $exception);
        }
        if ($claims === null) {
            throw new InvalidJwtException('The claims of a token are a JSON object (RFC 7519 section 7.2).');
        }

        /** @var array<string, mixed> $claims */
        return new UnverifiedJwt($jwt, $header, $claims);
    }
}
