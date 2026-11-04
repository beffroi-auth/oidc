<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

final class RequestObjectUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}
