<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\JweDecrypterInterface;
use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use function is_array;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function ltrim;
use function str_starts_with;
use function substr_count;
use Throwable;

/**
 * RFC 9101 §6.1, OIDC Core §6.1
 *
 * A JWE proves nothing about its sender: claims found inside are read as an unsigned object.
 */
final readonly class RequestObjectReader
{
    private const int JWE_SEPARATORS = 4;

    public function __construct(
        private CompactJwtReaderInterface $reader,
        private JweDecrypterInterface $decrypter,
    ) {
    }

    /**
     * @throws InvalidRequestObjectException
     * @throws KmsUnavailableException
     */
    public function read(Tenant $tenant, string $received): RequestObject
    {
        if (substr_count($received, '.') !== self::JWE_SEPARATORS) {
            return $this->object($received);
        }
        try {
            $payload = $this->decrypter->decrypt($tenant, $received);
        } catch (InvalidJweException $exception) {
            // The cause is not written back: a description never echoes what the sender chose (RFC 6749 §5.2).
            throw new InvalidRequestObjectException(
                'The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).',
                $exception,
            );
        }
        if (str_starts_with(ltrim($payload), '{')) {
            return new RequestObject(
                new UnverifiedJwt(
                    $received,
                    [
                        'alg' => UnsignedRequestObjects::ALGORITHM,
                    ],
                    $this->claims($payload),
                ),
            );
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
