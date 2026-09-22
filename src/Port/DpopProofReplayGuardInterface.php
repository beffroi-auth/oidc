<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\KeyConfirmation;

/**
 * Remembers the "jti" of a DPoP proof for as long as the proof may be presented (RFC 9449 §11.1), so
 * that one proof is used once. The store outlives the request and is shared by the workers of a
 * deployment: a proof replayed on another worker is a replay all the same.
 */
interface DpopProofReplayGuardInterface
{
    /**
     * @param KeyConfirmation $key the key the proof was signed with, which is what makes a "jti" unique:
     *                             it is the holder of the key that chose it
     * @param DateTimeImmutable $expiresAt when the proof stops being accepted, after which it may be forgotten
     *
     * @return bool true when the identifier had not been seen and is now remembered, false when it had
     */
    public function remember(KeyConfirmation $key, string $jti, DateTimeImmutable $expiresAt): bool;
}
