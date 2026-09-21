<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function array_any;
use function array_find;
use function hash_equals;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_string;

/**
 * The public keys a client publishes (RFC 7517 §5, RFC 7591 §2), inline in its registration or read back
 * from its "jwks_uri". Public keys only: a set is read as it is given, and a symmetric key is refused
 * (RFC 8725 §3.5), because a client that signs with a shared secret registers a secret, not a key.
 */
final readonly class ClientJwks
{
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
        foreach ($keys as $key) {
            $kty = $key['kty'] ?? null;
            if (! is_string($kty) || $kty === '') {
                throw new InvalidArgumentException('Every key of a JWK Set names its key type (RFC 7517 section 4.1).');
            }
            if ($kty === 'oct') {
                throw new InvalidArgumentException('A client publishes public keys; a symmetric key in a JWK Set is refused (RFC 8725 section 3.5).');
            }
        }
        $this->keys = $keys;
    }

    /**
     * The document as JSON gives it, read strictly: "keys" is a list of objects and nothing else is read.
     *
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
     * RFC 8705 §2.2: whether one of the keys published is this very certificate, which is what
     * "self_signed_tls_client_auth" authenticates against. A key publishes its certificate in its "x5c"
     * (RFC 7517 §4.7) or names it by thumbprint in its "x5t#S256" (§4.9); a key that does neither
     * publishes a public key and no certificate, and authenticates nobody here.
     *
     * The certificate is compared and not the key inside it: a certificate reissued on the same key is
     * another certificate, it is not the one the client registered, and it binds tokens to another
     * thumbprint (§3.1).
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
}
