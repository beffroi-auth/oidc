<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;

/**
 * RFC 9449 §11.1
 *
 * Shared by the workers of a deployment: a proof replayed on another worker is a replay all the same.
 */
interface DpopProofReplayGuardInterface
{
    /**
     * @return bool false when the identifier was already remembered
     */
    public function remember(KeyConfirmation $key, string $jti, DateTimeImmutable $expiresAt): bool;
}
