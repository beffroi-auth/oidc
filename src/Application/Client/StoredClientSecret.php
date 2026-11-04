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
     * @throws InvalidArgumentException
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
     * @throws InvalidArgumentException
     * @throws CoreInvalidArgumentException when the hash is not one this deployment can read
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
