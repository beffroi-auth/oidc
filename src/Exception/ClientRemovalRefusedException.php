<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * A client the administration API does not delete: one the deployment declares, which only its configuration takes
 * back, and the one the administrator acts through, whose deletion would end the administration they are doing.
 */
final class ClientRemovalRefusedException extends RuntimeException implements ExceptionInterface
{
    public static function declared(string $clientId): self
    {
        return new self(sprintf(
            'The client "%s" is declared in the configuration of the deployment, which alone takes it back.',
            $clientId,
        ));
    }

    public static function actedThrough(string $clientId): self
    {
        return new self(sprintf('An administrator does not delete the client they act through, "%s".', $clientId));
    }
}
