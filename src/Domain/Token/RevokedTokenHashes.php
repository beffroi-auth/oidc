<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_map;

/**
 * The tokens an event says were revoked, by their digest. Every use case that revokes a set of them,
 * a replayed authorization code, a reused refresh token family, a token given back at the revocation
 * endpoint, names them here: an event carries what happened by identifier, and that reading is written
 * once rather than at each of the three.
 */
final readonly class RevokedTokenHashes
{
    /**
     * @param list<HashedTokenInterface> $tokens
     *
     * @return list<string>
     */
    public static function of(array $tokens): array
    {
        return array_map(static fn (HashedTokenInterface $token): string => $token->tokenHash, $tokens);
    }
}
