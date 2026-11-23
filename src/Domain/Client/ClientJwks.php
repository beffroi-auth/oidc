<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use function array_any;
use function array_find;
use function count;
use function hash_equals;
use Beffroi\Core\Domain\Key\KeyEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Key\RsaModulus;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_string;
use function sprintf;

/**
 * RFC 7517 §5, RFC 7591 §2
 *
 * Public keys only: a client that signs with a shared secret registers a secret, not a key (RFC 8725 §3.5).
 */
final readonly class ClientJwks
{
    public const int MOST_KEYS = 100;

    /**
     * @var non-empty-list<array<string, mixed>>
     */
    public array $keys;

    /**
     * @param list<array<string, mixed>> $keys at least one
     */
    public function __construct(array $keys)
    {
        if ($keys === []) {
            throw new InvalidArgumentException('A JWK Set of a client holds at least one key (RFC 7517 section 5).');
        }
        if (count($keys) > self::MOST_KEYS) {
            throw new InvalidArgumentException(sprintf('A JWK Set of a client holds %d keys at most.', self::MOST_KEYS));
        }
        foreach ($keys as $key) {
            $kty = $key['kty'] ?? null;
            if (! is_string($kty) || $kty === '') {
                throw new InvalidArgumentException('Every key of a JWK Set names its key type (RFC 7517 section 4.1).');
            }
            if ($kty === 'oct') {
                throw new InvalidArgumentException('A client publishes public keys; a symmetric key in a JWK Set is refused (RFC 8725 section 3.5).');
            }
            if ($kty === 'RSA' && ! self::holdsALongEnoughModulus($key)) {
                throw new InvalidArgumentException(sprintf(
                    'An RSA key of a JWK Set carries a modulus "n" of %d bits at least (RFC 7518 sections 3.3, 3.5, 4.3 and 6.3.1).',
                    RsaModulus::MINIMUM_BITS,
                ));
            }
        }
        $this->keys = $keys;
    }

    /**
     * @param array<mixed> $document
     */
    public static function fromDocument(array $document): self
    {
        $keys = $document['keys'] ?? null;
        if (! is_array($keys)) {
            throw new InvalidArgumentException('A JWK Set is an object with a "keys" member (RFC 7517 section 5).');
        }
        $read = [];
        foreach ($keys as $key) {
            if (! is_array($key)) {
                throw new InvalidArgumentException('Every member of "keys" is a JWK object (RFC 7517 section 5).');
            }
            /** @var array<string, mixed> $key */
            $read[] = $key;
        }

        return new self($read);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function find(string $keyId): ?array
    {
        return array_find($this->keys, static fn (array $key): bool => ($key['kid'] ?? null) === $keyId);
    }

    public function holds(string $keyId): bool
    {
        return array_any($this->keys, static fn (array $key): bool => ($key['kid'] ?? null) === $keyId);
    }

    /**
     * RFC 7517 §4.2, §4.4
     *
     * A key that names the algorithm wins over one that says it encrypts, which wins over one that says
     * neither; the first published wins a tie.
     *
     * @return array<string, mixed>|null
     */
    public function encryptionKeyFor(KeyEncryptionAlgorithmInterface $algorithm): ?array
    {
        $named = null;
        $forEncryption = null;
        $unmarked = null;
        foreach ($this->keys as $key) {
            if (($key['kty'] ?? null) !== $algorithm->keyType()) {
                continue;
            }
            $use = $key['use'] ?? null;
            if ($use !== null && $use !== KeyUse::Encryption->value) {
                continue;
            }
            $registered = $key['alg'] ?? null;
            if ($registered !== null) {
                if ($registered === $algorithm->name()) {
                    $named ??= $key;
                }

                continue;
            }
            if ($use === KeyUse::Encryption->value) {
                $forEncryption ??= $key;

                continue;
            }
            $unmarked ??= $key;
        }

        return $named ?? $forEncryption ?? $unmarked;
    }

    /**
     * RFC 8705 §2.2
     *
     * The certificate is compared, not its key: one reissued on the same key binds tokens to another thumbprint.
     */
    public function publishes(ClientCertificate $certificate): bool
    {
        return array_any($this->keys, static function (array $key) use ($certificate): bool {
            $thumbprint = $key['x5t#S256'] ?? null;
            if (is_string($thumbprint) && hash_equals($certificate->x5tS256(), $thumbprint)) {
                return true;
            }
            $chain = $key['x5c'] ?? null;
            $leaf = is_array($chain) ? $chain[0] ?? null : null;
            $published = is_string($leaf) ? ClientCertificate::fromBase64($leaf) : null;

            return $published !== null && $published->isSameAs($certificate);
        });
    }

    /**
     * @param array<string, mixed> $key
     */
    private static function holdsALongEnoughModulus(array $key): bool
    {
        $modulus = $key['n'] ?? null;
        $bits = is_string($modulus) ? RsaModulus::bitsOf($modulus) : null;

        return $bits !== null && $bits >= RsaModulus::MINIMUM_BITS;
    }
}
