<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidJweException;
use Heidi\Core\Exception\KmsUnavailableException;
use Heidi\Core\Port\JweDecrypterInterface;
use Heidi\Oidc\Domain\Authorization\RequestObject;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;
use Heidi\Oidc\Exception\InvalidRequestObjectException;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use function is_array;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function ltrim;
use function str_starts_with;
use function substr_count;
use Throwable;

/**
 * What an endpoint has in hand once the request object has arrived (RFC 9101 §6.1, OIDC Core §6.1): the
 * object itself when the client sent it in clear, and the object inside the JWE when the client
 * encrypted it to a key the tenant publishes. The two endpoints that read an object, the authorization
 * endpoint and the pushed request endpoint, read it through here and read the same thing.
 *
 * A JWE is opened with the encryption keys of the tenant alone, which already refuse an "alg" or an
 * "enc" the provider is not wired with, an object that names no key, a key that signs and a key that has
 * retired. Nothing of what it carries is trusted for having been opened: the payload is a request object
 * like any other, read here and verified afterwards, the encryption saying who may read the request and
 * never who wrote it (OIDC Core §16.14).
 *
 * What a JWE carries is a JWS the client signed, which RFC 7519 §5.2 announces in its "cty", or the
 * claims themselves for the one client that registered "request_object_signing_alg": "none". The payload
 * says which of the two it is as plainly as the header does: a claims set is a JSON object, a nested
 * token is a compact serialization. An object read from claims is an unsigned object, and it is accepted
 * from that client and from no other, exactly as an unsigned object that arrived in clear.
 */
final readonly class RequestObjectReader
{
    /**
     * RFC 7516 §7.1: the five parts of a compact JWE, where the compact JWS of RFC 7515 §7.1 has three.
     */
    private const int JWE_SEPARATORS = 4;

    public function __construct(
        private CompactJwtReaderInterface $reader,
        private JweDecrypterInterface $decrypter,
    ) {
    }

    /**
     * @param string $received the object as the endpoint received it, by value or read back from the
     *                         URL the client published it at
     *
     * @throws InvalidRequestObjectException when the string is neither a JWT this provider reads nor a
     *                                       JWE it opens
     * @throws KmsUnavailableException when the KMS does not answer to open the key the object names,
     *                                 which is an outage and not a refusal
     */
    public function read(Tenant $tenant, string $received): RequestObject
    {
        if (substr_count($received, '.') !== self::JWE_SEPARATORS) {
            return $this->object($received);
        }
        try {
            $payload = $this->decrypter->decrypt($tenant, $received);
        } catch (InvalidJweException $exception) {
            // What did not open is not written back: an error description names the rule and never the
            // key, the algorithm or anything else the sender chose (RFC 6749 §5.2)
            throw new InvalidRequestObjectException('The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).', $exception);
        }
        if (str_starts_with(ltrim($payload), '{')) {
            return new RequestObject(new UnverifiedJwt($received, [
                'alg' => UnsignedRequestObjects::ALGORITHM,
            ], $this->claims($payload)));
        }

        return $this->object($payload);
    }

    /**
     * @throws InvalidRequestObjectException
     */
    private function object(string $compactJws): RequestObject
    {
        try {
            return new RequestObject($this->reader->read($compactJws));
        } catch (InvalidJwtException $exception) {
            throw new InvalidRequestObjectException('The request object is not a readable JWT (RFC 9101 section 4).', $exception);
        }
    }

    /**
     * @throws InvalidRequestObjectException
     *
     * @return array<string, mixed>
     */
    private function claims(string $payload): array
    {
        try {
            $claims = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new InvalidRequestObjectException('The claims of a request object are a JSON object (RFC 7519 section 7.2).', $exception);
        }
        if (! is_array($claims)) {
            throw new InvalidRequestObjectException('The claims of a request object are a JSON object (RFC 7519 section 7.2).');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }
}
