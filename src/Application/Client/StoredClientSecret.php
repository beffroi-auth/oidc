<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Application\Credential\StoredPasswordHash;
use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The document the secret the provider handed a client is kept as (RFC 7591 §3.2.1), one document in one
 * column so that the day a deployment encrypts it at rest is the day one column changes and nothing else.
 *
 * A secret is kept in one of the two shapes the domain has, and the document says which: the digest of a
 * secret the provider cannot read back, which is what a method that receives one verifies against
 * (RFC 6749 §2.3.1), or the secret itself, which is what a method that signs with it needs
 * (OIDC Core §9, "client_secret_jwt"). The two are not an open set the wiring decides, as the kinds of
 * confirmation are: either the provider can compute what the client computed, or it cannot.
 *
 * The digest is the document of a password hash and never a second shape of one (StoredPasswordHash),
 * which is also why this is a use case: reading the hash back names an algorithm, and the algorithm is
 * the class the wiring holds for that name (decision 0002).
 */
final readonly class StoredClientSecret
{
    private const string HASH = 'hash';

    private const string SHARED = 'shared';

    private StoredPasswordHash $hashes;

    public function __construct(PasswordAlgorithmsInterface $algorithms)
    {
        $this->hashes = new StoredPasswordHash($algorithms);
    }

    /**
     * @throws InvalidArgumentException when the secret is of neither shape this provider keeps
     *
     * @return array<string, mixed>
     */
    public function document(ClientSecretInterface $secret): array
    {
        if ($secret instanceof SharedClientSecret) {
            return [
                self::SHARED => $secret->value,
            ];
        }
        if ($secret instanceof HashedClientSecret) {
            return [
                self::HASH => $this->hashes->document($secret->hash),
            ];
        }

        throw new InvalidArgumentException('A client secret is kept hashed or shared, and nothing else.');
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidArgumentException when the document carries neither shape
     * @throws CoreInvalidArgumentException when the hash it carries is not one this deployment can read
     */
    public function of(array $document): ClientSecretInterface
    {
        $members = new Document($document);
        $shared = $members->nullableString(self::SHARED);
        if ($shared !== null) {
            return new SharedClientSecret($shared);
        }
        $hash = $members->nested(self::HASH) ?? throw new InvalidArgumentException('A stored client secret carries a "hash" or a "shared" member.');

        return new HashedClientSecret($this->hashes->of($hash));
    }
}
