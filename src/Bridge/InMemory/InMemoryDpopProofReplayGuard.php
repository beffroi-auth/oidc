<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Port\DpopProofReplayGuardInterface;
use function sprintf;

/**
 * One process only: workers that share no store would each accept the same proof.
 */
final class InMemoryDpopProofReplayGuard implements DpopProofReplayGuardInterface
{
    /**
     * @var array<string, DateTimeImmutable>
     */
    private array $seen = [];

    public function remember(KeyConfirmation $key, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $identifier = sprintf('%s|%s', $key->thumbprint, $jti);
        if (isset($this->seen[$identifier])) {
            return false;
        }
        $this->seen[$identifier] = $expiresAt;

        return true;
    }
}
