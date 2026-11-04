<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;

/**
 * OIDC Core §8.1
 *
 * Never in a migration or a fixture: a salt two deployments share makes their identifiers the same.
 */
interface PairwiseSaltInterface
{
    /**
     * @throws KmsUnavailableException
     * @throws RuntimeException when it can neither be read nor drawn
     *
     * @return non-empty-string opaque bytes, never published and never written to a log
     */
    public function saltOf(Tenant $tenant): string;
}
