<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\RefreshToken;
use Symfony\Component\Uid\Uuid;

/**
 * Where refresh tokens live between two refreshes (architecture §4.6). A token is looked up by its hash,
 * never by its value. Rotated and revoked tokens stay, so that the reuse of one can be told from an
 * unknown token and the family it belongs to can be revoked at once.
 */
interface RefreshTokenRepositoryInterface
{
    /**
     * @param string $tokenHash see RefreshToken::hash()
     */
    public function findByTokenHash(string $tokenHash): ?RefreshToken;

    /**
     * Every token of the family, rotated and revoked ones included.
     *
     * @return list<RefreshToken>
     */
    public function findByFamily(Uuid $family): array;

    /**
     * Every token descending from the code, whatever its state: the replay of a code revokes them all
     * (RFC 6749 §4.1.2).
     *
     * @param string $codeHash see AuthorizationCode::hash()
     *
     * @return list<RefreshToken>
     */
    public function findByAuthorizationCode(string $codeHash): array;

    public function save(RefreshToken $token): void;
}
