<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

final class SectorIdentifierUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}
