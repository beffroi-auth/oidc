<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KmsUnavailableException;
use Heidi\Core\Exception\RuntimeException;

/**
 * The salt a tenant computes its pairwise identifiers with (OIDC Core §8.1). It is a secret of the
 * deployment: it is drawn once, from the randomness the core draws every other secret from, and kept where
 * the sealed keys of that tenant are kept and sealed like them (architecture §3.3). It is never in a
 * migration and never in a fixture of a deployment, because a salt two deployments share is a salt that
 * makes their identifiers the same.
 *
 * Losing it does not leak anything and does not break a sign-in, and it is not recoverable either: every
 * pairwise identifier of every client of that tenant becomes a new identifier, and every relying party that
 * keyed an account on the old one no longer recognises its users. It is part of what a deployment backs up,
 * with the sealed keys and for the same reason.
 */
interface PairwiseSaltInterface
{
    /**
     * @throws KmsUnavailableException when the KMS of the tenant does not answer to seal or to open it
     * @throws RuntimeException when it can neither be read nor drawn
     *
     * @return non-empty-string opaque bytes, never published and never written to a log
     */
    public function saltOf(Tenant $tenant): string;
}
