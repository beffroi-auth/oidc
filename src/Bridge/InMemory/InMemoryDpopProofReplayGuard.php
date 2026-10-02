<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Port\DpopProofReplayGuardInterface;
use function sprintf;

/**
 * The proofs already seen, in the memory of one process: for the tests and for a deployment of one
 * worker. A deployment of several needs a store they share.
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
