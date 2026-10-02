<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\RefreshToken;
use Symfony\Component\Uid\Uuid;

/**
 * Where refresh tokens live (architecture §4.6). Rotated and revoked tokens stay, so that a reuse can be
 * told from an unknown token.
 */
interface RefreshTokenRepositoryInterface
{
    /**
     * @param string $tokenHash see DrawnSecret::digestOf()
     */
    public function findByTokenHash(string $tokenHash): ?RefreshToken;

    /**
     * @return list<RefreshToken> rotated and revoked ones included
     */
    public function findByFamily(Uuid $family): array;

    /**
     * @param string $codeHash see DrawnSecret::digestOf()
     *
     * @return list<RefreshToken> whatever their state
     */
    public function findByAuthorizationCode(string $codeHash): array;

    /**
     * @return list<RefreshToken> whatever their state
     */
    public function findBySession(Uuid $session): array;

    public function save(RefreshToken $token): void;
}
