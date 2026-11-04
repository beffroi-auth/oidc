<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function array_map;

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
