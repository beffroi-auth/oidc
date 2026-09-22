<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Exception\UseDpopNonceException;

/**
 * Whether a proof has to carry a value this provider handed out, and whether the one it carries is
 * still current (RFC 9449 §8). A provider that asks for none takes every proof its window accepts; one
 * that asks for a nonce decides when a proof was made and not only when its client says it was.
 */
interface DpopNonceInterface
{
    /**
     * @throws UseDpopNonceException when the proof carries no nonce and this provider asks for one, or
     *                               when the one it carries is not current; the exception carries the
     *                               fresh nonce to hand back
     */
    public function verify(?string $nonce, DateTimeImmutable $now): void;
}
